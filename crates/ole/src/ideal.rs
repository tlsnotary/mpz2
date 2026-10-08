//! Ideal ROLE.

use async_trait::async_trait;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use mpz_common::{
    Context, Flush,
    ideal::{CallSync, call_sync},
};
use mpz_fields::Field;
use mpz_ole_core::{
    ROLEReceiver, ROLESender, ROLESenderOutput,
    ideal::{IdealROLE as Core, IdealROLEError},
};

/// Returns a new ideal ROLE sender and receiver.
pub fn ideal_role<F: Field>() -> (IdealROLESender<F>, IdealROLEReceiver<F>) {
    let mut rng = StdRng::seed_from_u64(0);
    let core = Core::new(rng.random());
    let (sync_0, sync_1) = call_sync();
    (
        IdealROLESender {
            core: core.clone(),
            sync: sync_0,
        },
        IdealROLEReceiver { core, sync: sync_1 },
    )
}

/// Ideal ROLE sender.
#[derive(Debug)]
pub struct IdealROLESender<F> {
    core: Core<F>,
    sync: CallSync,
}

impl<F> ROLESender<F> for IdealROLESender<F>
where
    F: Field,
{
    type Error = IdealROLEError;
    type Future = <Core<F> as ROLESender<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROLESender::alloc(&mut self.core, count)
    }

    fn available(&self) -> usize {
        ROLESender::available(&self.core)
    }

    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>, Self::Error> {
        self.core.try_send_role(count)
    }

    fn queue_send_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_role(count)
    }
}

#[async_trait]
impl<F> Flush for IdealROLESender<F>
where
    F: Field,
{
    type Error = IdealROLEError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync.call(|| self.core.flush()).await.transpose()?;
        }

        Ok(())
    }
}

/// Ideal ROLE Receiver.
#[derive(Debug)]
pub struct IdealROLEReceiver<F> {
    core: Core<F>,
    sync: CallSync,
}

impl<F> ROLEReceiver<F> for IdealROLEReceiver<F>
where
    F: Field,
{
    type Error = IdealROLEError;
    type Future = <Core<F> as ROLEReceiver<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROLEReceiver::alloc(&mut self.core, count)
    }

    fn available(&self) -> usize {
        ROLEReceiver::available(&self.core)
    }

    fn try_recv_role(
        &mut self,
        count: usize,
    ) -> Result<mpz_ole_core::ROLEReceiverOutput<F>, Self::Error> {
        self.core.try_recv_role(count)
    }

    fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_role(count)
    }
}

#[async_trait]
impl<F> Flush for IdealROLEReceiver<F>
where
    F: Field,
{
    type Error = IdealROLEError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync.call(|| self.core.flush()).await.transpose()?;
        }

        Ok(())
    }
}
