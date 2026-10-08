//! Ideal functionality for Oblivious Linear Function Evaluation (OLE).

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{MaybeDone, Output, Sender, new_output};
use mpz_core::{Block, prg::Prg};
use mpz_fields::Field;

use crate::{
    OLEId, OLEShare, ROLEReceiver, ROLEReceiverOutput, ROLESender, ROLESenderOutput,
    test::role_shares,
};

type Error = IdealROLEError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct SenderState<F> {
    alloc: usize,
    ole_id: OLEId,
    queue: Vec<(usize, Sender<ROLESenderOutput<F>>)>,
}

impl<F> Default for SenderState<F> {
    fn default() -> Self {
        Self {
            alloc: Default::default(),
            ole_id: Default::default(),
            queue: Default::default(),
        }
    }
}

#[derive(Debug)]
struct ReceiverState<F> {
    alloc: usize,
    ole_id: OLEId,
    queue: Vec<(usize, Sender<ROLEReceiverOutput<F>>)>,
}

impl<F> Default for ReceiverState<F> {
    fn default() -> Self {
        Self {
            alloc: Default::default(),
            ole_id: Default::default(),
            queue: Default::default(),
        }
    }
}

/// Ideal ROLE functionality.
#[derive(Debug, Clone)]
pub struct IdealROLE<F> {
    inner: Arc<Mutex<Inner<F>>>,
}

#[derive(Debug)]
struct Inner<F> {
    prg: Prg,

    sender_state: SenderState<F>,
    receiver_state: ReceiverState<F>,

    sender_shares: Vec<OLEShare<F>>,
    receiver_shares: Vec<OLEShare<F>>,
}

impl<F> IdealROLE<F>
where
    F: Field,
{
    /// Creates a new ideal ROLE functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - PRG seed.
    pub fn new(seed: Block) -> Self {
        IdealROLE {
            inner: Arc::new(Mutex::new(Inner {
                prg: Prg::new_with_seed(seed.to_bytes()),
                sender_state: SenderState::default(),
                receiver_state: ReceiverState::default(),
                sender_shares: Default::default(),
                receiver_shares: Default::default(),
            })),
        }
    }

    /// Performs ROLEs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(ROLESenderOutput<F>, ROLEReceiverOutput<F>)> {
        let mut sender_output = self.queue_send_role(count)?;
        let mut receiver_output = self.queue_recv_role(count)?;

        self.flush()?;

        Ok((
            sender_output.try_recv().unwrap().unwrap(),
            receiver_output.try_recv().unwrap().unwrap(),
        ))
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let this = self.inner.lock().unwrap();
        let sender_count = this.sender_state.alloc;
        let receiver_count = this.receiver_state.alloc;

        sender_count > 0 || receiver_count > 0
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        if this.sender_state.alloc != this.receiver_state.alloc {
            return Err(Error::new(format!(
                "sender and receiver alloc out of sync: {} != {}",
                this.sender_state.alloc, this.receiver_state.alloc
            )));
        }

        let count = this.sender_state.alloc;

        let (sender_shares, receiver_shares): (Vec<_>, Vec<_>) =
            (0..count).map(|_| role_shares(&mut this.prg)).unzip();

        this.sender_shares.extend_from_slice(&sender_shares);
        this.receiver_shares.extend_from_slice(&receiver_shares);

        this.sender_state.alloc = 0;
        this.receiver_state.alloc = 0;

        let mut i = 0;
        for (count, sender) in mem::take(&mut this.sender_state.queue) {
            let shares = this.sender_shares[i..i + count].to_vec();
            i += count;
            sender.send(ROLESenderOutput {
                id: this.sender_state.ole_id.next(),
                shares,
            });
        }
        this.sender_shares.drain(..i);

        i = 0;
        for (count, sender) in mem::take(&mut this.receiver_state.queue) {
            let shares = this.receiver_shares[i..i + count].to_vec();
            i += count;
            sender.send(ROLEReceiverOutput {
                id: this.receiver_state.ole_id.next(),
                shares,
            });
        }
        this.receiver_shares.drain(..i);

        Ok(())
    }
}

impl<F> ROLESender<F> for IdealROLE<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<ROLESenderOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.sender_shares.len()
    }

    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>> {
        let mut this = self.inner.lock().unwrap();
        if count > this.sender_shares.len() {
            return Err(Error::new(format!(
                "not enough sender ROLEs available: {} < {}",
                this.sender_shares.len(),
                count
            )));
        }

        let id = this.sender_state.ole_id.next();
        let shares = this.sender_shares.drain(..count).collect();

        Ok(ROLESenderOutput { id, shares })
    }

    fn queue_send_role(&mut self, count: usize) -> Result<MaybeDone<ROLESenderOutput<F>>> {
        let mut this = self.inner.lock().unwrap();
        let (send, recv) = new_output();

        let available = this.sender_shares.len();
        if available >= count {
            let id = this.sender_state.ole_id.next();
            let shares = this.sender_shares.drain(..count).collect();

            send.send(ROLESenderOutput { id, shares });
        } else {
            this.sender_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

impl<F> ROLEReceiver<F> for IdealROLE<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<ROLEReceiverOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.receiver_shares.len()
    }

    fn try_recv_role(&mut self, count: usize) -> Result<ROLEReceiverOutput<F>> {
        let mut this = self.inner.lock().unwrap();
        if count > this.receiver_shares.len() {
            return Err(Error::new(format!(
                "not enough receiver ROLEs available: {} < {}",
                this.receiver_shares.len(),
                count
            )));
        }

        let id = this.sender_state.ole_id.next();
        let shares = this.receiver_shares.drain(..count).collect();

        Ok(ROLEReceiverOutput { id, shares })
    }

    fn queue_recv_role(&mut self, count: usize) -> Result<MaybeDone<ROLEReceiverOutput<F>>> {
        let mut this = self.inner.lock().unwrap();
        let (send, recv) = new_output();

        let available = this.receiver_shares.len();
        if available >= count {
            let id = this.receiver_state.ole_id.next();
            let shares = this.receiver_shares.drain(..count).collect();

            send.send(ROLEReceiverOutput { id, shares });
        } else {
            this.receiver_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

/// Error for [`IdealROLE`].
#[derive(Debug, thiserror::Error)]
#[error("ideal ROLE error: {0}")]
pub struct IdealROLEError(String);

impl IdealROLEError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    use crate::test::assert_ole;

    #[test]
    fn test_ideal_role_p256() {
        test_ideal_role::<P256>();
    }

    #[test]
    fn test_ideal_role_gf2_128() {
        test_ideal_role::<Gf2_128>();
    }

    fn test_ideal_role<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut ideal = IdealROLE::<F>::new(rng.random());

        let count = 128;

        ROLESender::<F>::alloc(&mut ideal, count).unwrap();
        ROLEReceiver::<F>::alloc(&mut ideal, count).unwrap();
        ideal.flush().unwrap();

        let (
            ROLESenderOutput {
                id: sender_id,
                shares: sender_shares,
            },
            ROLEReceiverOutput {
                id: receiver_id,
                shares: receiver_shares,
            },
        ) = ideal.transfer(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        sender_shares
            .into_iter()
            .zip(receiver_shares)
            .for_each(|(s, r)| assert_ole(s, r))
    }
}
