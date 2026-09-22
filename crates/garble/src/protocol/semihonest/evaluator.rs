use std::sync::Arc;

use async_trait::async_trait;
use hashbrown::HashMap;
use tokio::sync::Mutex;

use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_garble_core::{EvaluatorOutput, GarbledCircuit, evaluate_garbled_circuits};
use mpz_memory_core::{DecodeFuture, Memory, Slice, View, binary::Binary};
use mpz_ot::cot::COTReceiver;
use mpz_vm_core::{Call, Callable, Execute, Result, VmError};

use crate::{
    evaluator::receive_garbled_circuit, protocol::semihonest::take_preprocess_calls,
    store::EvaluatorStore,
};

/// Semi-honest evaluator.
#[derive(Debug)]
pub struct Evaluator<COT> {
    store: Arc<Mutex<EvaluatorStore<COT>>>,
    call_stack: Vec<(Call, Slice)>,
    preprocessed: HashMap<Slice, (Call, GarbledCircuit)>,
}

impl<COT> Evaluator<COT> {
    /// Creates a new evaluator.
    pub fn new(cot: COT) -> Self {
        Self {
            store: Arc::new(Mutex::new(EvaluatorStore::new(cot))),
            call_stack: Vec::new(),
            preprocessed: HashMap::new(),
        }
    }

    fn take_execute_calls(&mut self) -> Vec<(Call, Slice)> {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            // Extract only a call which has all its inputs committed.
            .extract_if(.., |(call, _)| {
                call.inputs()
                    .iter()
                    .all(|input| store.is_committed_raw(*input))
            })
            .collect()
    }

    fn execute_preprocessed(&mut self) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        loop {
            let (calls, outputs): (Vec<_>, Vec<_>) = self
                .preprocessed
                .extract_if(|_, (call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| store.is_committed_raw(*input))
                })
                .map(|(output, (call, garbled_circuit))| {
                    let (circ, inputs) = call.into_parts();
                    let mut input_macs = Vec::with_capacity(circ.inputs().len());
                    for input in inputs {
                        input_macs.extend_from_slice(
                            store
                                .try_get_macs(input)
                                .expect("committed MACs should be set"),
                        );
                    }

                    ((circ, input_macs, garbled_circuit), output)
                })
                .unzip();

            if calls.is_empty() {
                break;
            }

            for (
                EvaluatorOutput {
                    outputs: output_macs,
                },
                output,
            ) in evaluate_garbled_circuits(calls)
                .map_err(VmError::execute)?
                .into_iter()
                .zip(outputs)
            {
                store
                    .set_output(output, &output_macs)
                    .map_err(VmError::memory)?;
            }

            store.flush_decode().map_err(VmError::memory)?;
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> Arc<Mutex<EvaluatorStore<COT>>> {
        self.store.clone()
    }
}

impl<COT> Memory<Binary> for Evaluator<COT> {
    type Error = VmError;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.store.try_lock().unwrap().is_alloc_raw(slice)
    }

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store
            .try_lock()
            .unwrap()
            .alloc_raw(size)
            .map_err(VmError::memory)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.store.try_lock().unwrap().is_assigned_raw(slice)
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .assign_raw(slice, value)
            .map_err(VmError::memory)
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.store.try_lock().unwrap().is_committed_raw(slice)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .commit_raw(slice)
            .map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .get_raw(slice)
            .map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .decode_raw(slice)
            .map_err(VmError::memory)
    }
}

impl<COT> View<Binary> for Evaluator<COT>
where
    COT: COTReceiver<bool, Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_public_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_private_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_blind_raw(slice)
            .map_err(VmError::view)
    }
}

impl<COT> Callable<Binary> for Evaluator<COT> {
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self
            .store
            .try_lock()
            .unwrap()
            .alloc_output(call.circ().outputs().len());
        self.call_stack.push((call, output));
        Ok(output)
    }
}

#[async_trait]
impl<COT> Execute for Evaluator<COT>
where
    COT: COTReceiver<bool, Block> + Flush + Send + 'static,
    COT::Future: Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.store.try_lock().unwrap().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        if store.wants_flush() {
            store.flush(ctx).await.map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        // The first call in the call stack is always ready for preprocessing.
        !self.call_stack.is_empty()
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
        let mut cot = self.store.try_lock().unwrap().acquire_cot();

        let mut call_stack = std::mem::take(&mut self.call_stack);

        let (_, preprocessed) = ctx
            .try_join(
                move |ctx| {
                    Box::pin(async move {
                        // This flush is primarily intended to perform OT setup
                        // concurrently with preprocessing.
                        cot.flush(ctx).await.map_err(VmError::execute)
                    })
                },
                move |ctx| {
                    Box::pin(async move {
                        let mut preprocessed = Vec::new();

                        while !call_stack.is_empty() {
                            let calls = take_preprocess_calls(&mut call_stack);

                            // There must be at least one call ready for
                            // preprocessing
                            // in a non-empty call stack.
                            debug_assert!(!calls.is_empty());

                            let mut outputs = ctx
                                .map(calls, move |ctx, (call, output): (Call, Slice)| {
                                    Box::pin(async move {
                                        let garbled_circuit =
                                            receive_garbled_circuit(ctx, call.circ())
                                                .await
                                                .map_err(VmError::execute)?;
                                        Ok::<_, VmError>((call, output, garbled_circuit))
                                    })
                                })
                                .await
                                .map_err(VmError::execute)?;

                            preprocessed.append(&mut outputs);
                        }

                        Ok::<_, VmError>(preprocessed)
                    })
                },
            )
            .await
            .map_err(VmError::execute)??;

        let mut store = self.store.try_lock().unwrap();
        for output in preprocessed {
            let (call, output, garbled_circuit) = output?;

            self.preprocessed.insert(output, (call, garbled_circuit));
            store
                .mark_output_preprocessed(output)
                .map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_execute(&self) -> bool {
        let store = self.store.try_lock().unwrap();
        self.preprocessed.iter().any(|(_, (call, _))| {
            call.inputs()
                .iter()
                .all(|input| store.is_committed_raw(*input))
        }) || self.call_stack.iter().any(|(call, _)| {
            call.inputs()
                .iter()
                .all(|input| store.is_committed_raw(*input))
        })
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<()> {
        if !self.preprocessed.is_empty() {
            self.execute_preprocessed()?;
        }

        while !self.call_stack.is_empty() {
            let calls = self.take_execute_calls();

            if calls.is_empty() {
                break;
            }

            let store = self.store.clone();
            let outputs = ctx
                .map(calls, move |ctx, (call, output): (Call, Slice)| {
                    let store = store.clone();
                    Box::pin(async move { evaluate(ctx, store, call, output).await })
                })
                .await
                .map_err(VmError::execute)?;

            outputs.into_iter().collect::<Result<()>>()?;
        }

        self.store
            .try_lock()
            .unwrap()
            .flush_decode()
            .map_err(VmError::memory)?;

        Ok(())
    }
}

async fn evaluate<COT>(
    ctx: &mut Context,
    store: Arc<Mutex<EvaluatorStore<COT>>>,
    call: Call,
    output: Slice,
) -> Result<()> {
    let (circ, inputs) = call.into_parts();

    let mut input_macs = Vec::with_capacity(circ.inputs().len());
    {
        let lock = store.lock().await;
        for input in inputs {
            input_macs.extend_from_slice(lock.try_get_macs(input).map_err(VmError::memory)?);
        }
    }

    let EvaluatorOutput {
        outputs: output_macs,
    } = crate::evaluator::evaluate(ctx, circ, &input_macs)
        .await
        .map_err(VmError::execute)?;

    let mut lock = store.lock().await;
    lock.set_output(output, &output_macs)
        .map_err(VmError::memory)?;

    Ok(())
}
