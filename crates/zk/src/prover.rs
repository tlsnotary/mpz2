use async_trait::async_trait;
use blake3::Hasher;
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_ot::rcot::{RCOTReceiver, RCOTReceiverOutput};
use mpz_vm_core::{
    Call, Callable, Execute, Result as VmResult, VmError,
    memory::{DecodeFuture, Memory, Repr, Slice, View, binary::Binary, correlated::Mac},
};
use mpz_zk_core::{Prover as Core, ProverError, store::ProverStore};
use serio::SinkExt;

use crate::{callstack::CallStack, config::ProverConfig};

#[derive(Debug)]
pub struct Prover<OT> {
    config: ProverConfig,
    store: ProverStore,
    ot: OT,
    callstack: CallStack,
    transcript: Hasher,
}

impl<OT> Prover<OT> {
    /// Creates a new prover.
    pub fn new(config: ProverConfig, ot: OT) -> Self {
        Self {
            config,
            store: ProverStore::new(),
            ot,
            callstack: CallStack::default(),
            transcript: Hasher::default(),
        }
    }

    /// Returns the MACs.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to return the MACs for.
    pub fn get_macs<R>(&self, value: R) -> Result<&[Mac], ProverError>
    where
        R: Repr<Binary>,
    {
        let slice = value.to_raw();
        let macs = self.store.try_get_macs(slice)?;

        Ok(macs)
    }
}

#[async_trait]
impl<OT> Execute for Prover<OT>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.ot.wants_flush() || self.store.wants_macs() || self.store.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> VmResult<()> {
        if self.ot.wants_flush() {
            self.ot.flush(ctx).await.map_err(VmError::execute)?;
        }

        if self.store.wants_macs() {
            let RCOTReceiverOutput {
                msgs: macs,
                choices: masks,
                ..
            } = self
                .ot
                .try_recv_rcot(self.store.mac_count())
                .map_err(VmError::execute)?;
            let masks = BitVec::from_iter(masks);
            let macs = Mac::from_blocks(macs);

            self.store
                .set_macs(&masks, &macs)
                .map_err(VmError::memory)?;
        }

        while self.store.wants_flush() {
            let flush = self
                .store
                .send_flush(&mut self.transcript)
                .map_err(VmError::memory)?;
            ctx.io_mut().send(flush).await?;
            self.store.complete_flush().map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        false
    }

    async fn preprocess(&mut self, _ctx: &mut Context) -> VmResult<()> {
        Ok(())
    }

    fn wants_execute(&self) -> bool {
        self.callstack.iter().any(|(call, _)| {
            call.inputs()
                .iter()
                .all(|input| self.store.is_committed_raw(*input))
        })
    }

    async fn execute(&mut self, ctx: &mut Context) -> VmResult<()> {
        let mut prover = Core::default();

        while !self.callstack.is_empty() {
            let ready_calls: Vec<_> = self
                .callstack
                .extract_if(
                    self.config.batch_size().saturating_sub(prover.pending()),
                    |call| {
                        call.inputs()
                            .iter()
                            .all(|input| self.store.is_committed_raw(*input))
                    },
                )
                .map(|(call, output)| {
                    let input_macs = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_macs(*input).expect("macs should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    let (circ, _) = call.into_parts();

                    (circ, input_macs, output)
                })
                .collect();

            if ready_calls.is_empty() {
                break;
            }

            let mut tasks = Vec::with_capacity(ready_calls.len());
            for (circ, input_macs, output) in ready_calls {
                let RCOTReceiverOutput {
                    choices: gate_masks,
                    msgs: gate_macs,
                    ..
                } = self
                    .ot
                    .try_recv_rcot(circ.and_count())
                    .map_err(VmError::execute)?;
                let gate_macs = Mac::from_blocks(gate_macs);

                let execute = prover
                    .execute(circ, &input_macs, &gate_masks, &gate_macs)
                    .map_err(VmError::execute)?;
                tasks.push((execute, output));
            }

            let outputs = ctx
                .map(tasks, move |ctx, (mut execute, output)| {
                    Box::pin(async move {
                        let mut iter = execute.iter();
                        loop {
                            // Stream the `adjust` bits to avoid buffering them
                            // in memory.
                            let adjust: BitVec = BitVec::from_iter(iter.by_ref().take(8000));

                            if !adjust.is_empty() {
                                ctx.io_mut().send(adjust).await?;
                            } else {
                                break;
                            }
                        }

                        let output_macs = execute.finish().map_err(VmError::execute)?;

                        Ok((output, output_macs))
                    })
                })
                .await
                .map_err(VmError::execute)?
                .into_iter()
                .collect::<VmResult<Vec<_>>>()?;

            for (output, output_macs) in outputs {
                self.store
                    .set_output_macs(output, &output_macs)
                    .map_err(VmError::memory)?;
            }

            if prover.pending() >= self.config.batch_size() {
                let RCOTReceiverOutput {
                    choices: svole_choices,
                    msgs: svole_ev,
                    ..
                } = self.ot.try_recv_rcot(128).map_err(VmError::execute)?;

                let uv = prover
                    .check(&mut self.transcript, &svole_choices, &svole_ev)
                    .map_err(VmError::execute)?;
                ctx.io_mut().send(uv).await?;
            }
        }

        // Check the last partial batch.
        if prover.wants_check() {
            let RCOTReceiverOutput {
                choices: svole_choices,
                msgs: svole_ev,
                ..
            } = self.ot.try_recv_rcot(128).map_err(VmError::execute)?;

            let uv = prover
                .check(&mut self.transcript, &svole_choices, &svole_ev)
                .map_err(VmError::execute)?;
            ctx.io_mut().send(uv).await?;
        }

        // Pre-allocate OTs for the next execute() call's final check
        // if circuits remain in the callstack.
        if !self.callstack.is_empty() {
            self.ot.alloc(128).map_err(VmError::execute)?;
        }

        Ok(())
    }
}

impl<OT> Callable<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    fn call_raw(&mut self, call: Call) -> VmResult<Slice> {
        let output = self.store.alloc_output(call.circ().outputs().len());

        let count = call.circ().and_count();

        if count == 0 {
            self.callstack.push((call, output));
            return Ok(output);
        }

        // The number of additional consistency checks to allocate for.
        let mut check_count = 0;

        let partial_len = self.callstack.and_count() % self.config.batch_size();

        if partial_len == 0 {
            // Allocate for the first batch or when the previous batch
            // landed exactly on the batch boundary.
            check_count += 1;
        }

        // Using -1 because we allocate whenever a batch boundary is
        // **crossed**, not when we land exactly on the boundary.
        check_count += (partial_len + count - 1) / self.config.batch_size();

        self.ot
            .alloc(count + check_count * 128)
            .map_err(VmError::execute)?;

        self.callstack.push((call, output));

        Ok(output)
    }
}

impl<OT> Memory<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = VmError;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.store.is_alloc_raw(slice)
    }

    fn alloc_raw(&mut self, size: usize) -> VmResult<Slice> {
        self.store.alloc_raw(size).map_err(VmError::memory)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.store.is_assigned_raw(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> VmResult<()> {
        self.store.assign_raw(slice, data).map_err(VmError::memory)
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.store.is_committed_raw(slice)
    }

    fn commit_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.commit_raw(slice).map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> VmResult<Option<BitVec>> {
        self.store.get_raw(slice).map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> VmResult<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(VmError::memory)
    }
}

impl<OT> View<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_public_raw(slice).map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_private_raw(slice).map_err(VmError::view)?;

        self.ot.alloc(slice.len()).map_err(VmError::view)?;

        Ok(())
    }

    fn mark_blind_raw(&mut self, _slice: Slice) -> VmResult<()> {
        Err(VmError::view(
            "marking as blind is not allowed for zk prover",
        ))
    }
}
