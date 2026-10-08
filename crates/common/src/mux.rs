//! Multiplexing types.

use crate::io::Io;

/// A multiplexer.
pub trait Mux {
    /// Opens a new I/O channel for the given context ID.
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error>;
}

#[cfg(any(test, feature = "test-utils"))]
mod test_utils {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use serio::channel::{MemoryDuplex, duplex};

    use crate::{io::Io, mux::Mux};

    #[derive(Debug, Default)]
    struct State {
        exists: HashSet<Vec<u8>>,
        waiting_a: HashMap<Vec<u8>, MemoryDuplex>,
        waiting_b: HashMap<Vec<u8>, MemoryDuplex>,
    }

    #[derive(Debug, Clone, Copy)]
    enum Role {
        A,
        B,
    }

    /// A test framed mux.
    #[derive(Debug, Clone)]
    pub struct TestFramedMux {
        role: Role,
        buffer: usize,
        state: Arc<Mutex<State>>,
    }

    impl Mux for TestFramedMux {
        fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
            let mut state = self.state.lock().unwrap();

            if let Some(channel) = match self.role {
                Role::A => state.waiting_a.remove(id),
                Role::B => state.waiting_b.remove(id),
            } {
                Ok(Io::from_channel(channel))
            } else {
                if !state.exists.insert(id.to_vec()) {
                    return Err(std::io::Error::other("duplicate stream id"));
                }

                let (a, b) = duplex(self.buffer);

                match self.role {
                    Role::A => {
                        state.waiting_b.insert(id.to_vec(), b);
                        Ok(Io::from_channel(a))
                    }
                    Role::B => {
                        state.waiting_a.insert(id.to_vec(), a);
                        Ok(Io::from_channel(b))
                    }
                }
            }
        }
    }

    /// Creates a test pair of framed mux instances.
    pub fn test_framed_mux(buffer: usize) -> (TestFramedMux, TestFramedMux) {
        let state = Arc::new(Mutex::new(State::default()));

        (
            TestFramedMux {
                role: Role::A,
                buffer,
                state: state.clone(),
            },
            TestFramedMux {
                role: Role::B,
                buffer,
                state,
            },
        )
    }

    #[cfg(test)]
    mod tests {
        use crate::mux::Mux;
        use serio::{SinkExt, StreamExt};

        #[test]
        fn test_framed_mux() {
            let (a, b) = super::test_framed_mux(1);

            futures::executor::block_on(async {
                let mut a_0 = a.open(&[0]).unwrap();
                let mut b_0 = b.open(&[0]).unwrap();

                let mut a_1 = a.open(&[1]).unwrap();
                let mut b_1 = b.open(&[1]).unwrap();

                a_0.send(42u8).await.unwrap();
                assert_eq!(b_0.next::<u8>().await.unwrap().unwrap(), 42);

                a_1.send(69u8).await.unwrap();
                assert_eq!(b_1.next::<u8>().await.unwrap().unwrap(), 69u8);
            })
        }

        #[test]
        fn test_framed_mux_duplicate() {
            let (a, b) = super::test_framed_mux(1);

            futures::executor::block_on(async {
                let _ = a.open(&[0]).unwrap();
                let _ = b.open(&[0]).unwrap();

                assert!(a.open(&[0]).is_err());
                assert!(b.open(&[0]).is_err());
            })
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::{TestFramedMux, test_framed_mux};
