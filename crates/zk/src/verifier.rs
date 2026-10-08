use async_trait::async_trait;
use blake3::Hasher;
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_ot::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core::{
    Call, Callable, Execute, Result as VmResult, VmError,
    memory::{
        DecodeFuture, Memory, Repr, Slice, View,
        binary::Binary,
        correlated::{Delta, Key},
    },
};
use mpz_zk_core::{Verifier as Core, VerifierError, store::VerifierStore};
use serio::stream::IoStreamExt;

use crate::{callstack::CallStack, config::VerifierConfig};

#[derive(Debug)]
pub struct Verifier<OT> {
    config: VerifierConfig,
    store: VerifierStore,
    ot: OT,
    callstack: CallStack,
    transcript: Hasher,
}

impl<OT> Verifier<OT> {
    /// Creates a new verifier.
    pub fn new(config: VerifierConfig, delta: Delta, ot: OT) -> Self {
        Self {
            config,
            store: VerifierStore::new(delta),
            ot,
            callstack: CallStack::default(),
            transcript: Hasher::default(),
        }
    }

    /// Returns the global MAC correlation, `delta`.
    pub fn delta(&self) -> &Delta {
        self.store.delta()
    }

    /// Returns the keys.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to return the keys for.
    pub fn get_keys<R>(&self, value: R) -> Result<&[Key], VerifierError>
    where
        R: Repr<Binary>,
    {
        let slice = value.to_raw();
        let keys = self.store.try_get_keys(slice)?;

        Ok(keys)
    }
}

#[async_trait]
impl<OT> Execute for Verifier<OT>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.ot.wants_flush() || self.store.wants_keys() || self.store.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> VmResult<()> {
        if self.ot.wants_flush() {
            self.ot.flush(ctx).await.map_err(VmError::execute)?;
        }

        if self.store.wants_keys() {
            let RCOTSenderOutput { keys, .. } = self
                .ot
                .try_send_rcot(self.store.key_count())
                .map_err(VmError::execute)?;
            let keys = Key::from_blocks(keys);

            self.store.set_keys(&keys).map_err(VmError::memory)?;
        }

        while self.store.wants_flush() {
            self.store.mark_flush_pending().map_err(VmError::memory)?;
            let flush = ctx.io_mut().expect_next().await?;
            self.store
                .receive_flush(flush, &mut self.transcript)
                .map_err(VmError::memory)?;
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
        let mut verifier = Core::new(*self.store.delta());

        while !self.callstack.is_empty() {
            let ready_calls: Vec<_> = self
                .callstack
                .extract_if(
                    self.config.batch_size().saturating_sub(verifier.pending()),
                    |call| {
                        call.inputs()
                            .iter()
                            .all(|input| self.store.is_committed_raw(*input))
                    },
                )
                .map(|(call, output)| {
                    let input_keys = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_keys(*input).expect("keys should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    let (circ, _) = call.into_parts();
                    (circ, input_keys, output)
                })
                .collect();

            if ready_calls.is_empty() {
                break;
            }

            let mut tasks = Vec::with_capacity(ready_calls.len());
            for (circ, input_keys, output) in ready_calls {
                let RCOTSenderOutput {
                    keys: gate_keys, ..
                } = self
                    .ot
                    .try_send_rcot(circ.and_count())
                    .map_err(VmError::execute)?;
                let gate_keys = Key::from_blocks(gate_keys);

                let execute = verifier
                    .execute(circ, &input_keys, &gate_keys)
                    .map_err(VmError::execute)?;
                tasks.push((execute, output));
            }

            let outputs = ctx
                .map(tasks, move |ctx, (mut execute, output)| {
                    Box::pin(async move {
                        let mut consumer = execute.consumer();
                        while consumer.wants_adjust() {
                            let adjust: BitVec = ctx.io_mut().expect_next().await?;
                            for bit in adjust {
                                consumer.next(bit);
                            }
                        }

                        let output_keys = execute.finish().map_err(VmError::execute)?;

                        Ok((output, output_keys))
                    })
                })
                .await
                .map_err(VmError::execute)?
                .into_iter()
                .collect::<VmResult<Vec<_>>>()?;

            for (output, output_keys) in outputs {
                self.store
                    .set_output_keys(output, &output_keys)
                    .map_err(VmError::memory)?;
            }

            if verifier.pending() >= self.config.batch_size() {
                let RCOTSenderOutput {
                    keys: svole_keys, ..
                } = self.ot.try_send_rcot(128).map_err(VmError::execute)?;

                let uv = ctx.io_mut().expect_next().await?;
                verifier
                    .check(&mut self.transcript, &svole_keys, uv)
                    .map_err(VmError::execute)?;
            }
        }

        // Check the last partial batch.
        if verifier.wants_check() {
            let RCOTSenderOutput {
                keys: svole_keys, ..
            } = self.ot.try_send_rcot(128).map_err(VmError::execute)?;

            let uv = ctx.io_mut().expect_next().await?;
            verifier
                .check(&mut self.transcript, &svole_keys, uv)
                .map_err(VmError::execute)?;
        }

        // Pre-allocate OTs for the next execute() call's final check
        // if circuits remain in the callstack.
        if !self.callstack.is_empty() {
            self.ot.alloc(128).map_err(VmError::execute)?;
        }

        Ok(())
    }
}

impl<OT> Callable<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
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

impl<OT> Memory<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
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

impl<OT> View<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_public_raw(slice).map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, _slice: Slice) -> VmResult<()> {
        Err(VmError::view(
            "marking as private is not allowed for zk verifier",
        ))
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_blind_raw(slice).map_err(VmError::view)?;
        self.ot.alloc(slice.len()).map_err(VmError::view)?;

        Ok(())
    }
}
