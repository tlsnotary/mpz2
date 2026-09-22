use crate::{
    Circuit,
    components::{Feed, Gate, Node},
};

/// Error for [`CircuitBuilder`].
#[derive(Debug, thiserror::Error)]
#[error("circuit builder error")]
pub struct BuilderError {
    _private: (),
}

/// A circuit builder.
#[derive(Default)]
pub struct CircuitBuilder {
    feed_id: usize,
    inputs: Vec<Node<Feed>>,
    outputs: Vec<Node<Feed>>,
    gates: Vec<Gate>,

    and_count: usize,
    xor_count: usize,
}

impl CircuitBuilder {
    /// Creates a new circuit builder
    pub fn new() -> Self {
        Self {
            // ids 0 and 1 are reserved for constant zero and one
            feed_id: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            gates: Vec::new(),
            and_count: 0,
            xor_count: 0,
        }
    }

    /// Returns constant zero node.
    pub fn get_const_zero(&self) -> Node<Feed> {
        Node::<Feed>::new(0)
    }

    /// Returns constant one node.
    pub fn get_const_one(&self) -> Node<Feed> {
        Node::<Feed>::new(1)
    }

    /// Adds an input to the circuit.
    pub fn add_input(&mut self) -> Node<Feed> {
        let node = self.add_feed();
        self.inputs.push(node);
        node
    }

    /// Adds an output to the circuit.
    pub fn add_output(&mut self, node: Node<Feed>) {
        self.outputs.push(node);
    }

    /// Adds a feed to the circuit.
    pub(crate) fn add_feed(&mut self) -> Node<Feed> {
        let feed = Node::<Feed>::new(self.feed_id);
        self.feed_id += 1;

        feed
    }

    /// Adds an XOR gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The first input to the gate.
    /// * `y` - The second input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub fn add_xor_gate(&mut self, x: Node<Feed>, y: Node<Feed>) -> Node<Feed> {
        // if either input is a constant, we can simplify the gate
        if (x.id() == 0 && y.id() == 0) || (x.id() == 1 && y.id() == 1) {
            self.get_const_zero()
        } else if x.id() == 0 {
            y
        } else if y.id() == 0 {
            x
        } else if x.id() == 1 {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: y.into(),
                z: out,
            });
            out
        } else if y.id() == 1 {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: x.into(),
                z: out,
            });
            out
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::Xor {
                x: x.into(),
                y: y.into(),
                z: out,
            });
            self.xor_count += 1;
            out
        }
    }

    /// Adds an AND gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The first input to the gate.
    /// * `y` - The second input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub fn add_and_gate(&mut self, x: Node<Feed>, y: Node<Feed>) -> Node<Feed> {
        // if either input is a constant, we can simplify the gate
        if x.id() == 0 || y.id() == 0 {
            self.get_const_zero()
        } else if x.id() == 1 {
            y
        } else if y.id() == 1 {
            x
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::And {
                x: x.into(),
                y: y.into(),
                z: out,
            });
            self.and_count += 1;
            out
        }
    }

    /// Adds an INV gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub fn add_inv_gate(&mut self, x: Node<Feed>) -> Node<Feed> {
        if x.id() == 0 {
            self.get_const_one()
        } else if x.id() == 1 {
            self.get_const_zero()
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: x.into(),
                z: out,
            });
            out
        }
    }

    /// Adds an identity gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub fn add_id_gate(&mut self, x: Node<Feed>) -> Node<Feed> {
        if x.id() == 0 {
            self.get_const_zero()
        } else if x.id() == 1 {
            self.get_const_one()
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::Id {
                x: x.into(),
                z: out,
            });
            out
        }
    }

    /// Builds the circuit.
    pub fn build(mut self) -> Result<Circuit, BuilderError> {
        // First shift all IDs left by 2 since constants are factored out when
        // adding gates.
        self.inputs.iter_mut().for_each(|input| input.shift_left(2));
        self.gates.iter_mut().for_each(|gate| gate.shift_left(2));
        self.outputs
            .iter_mut()
            .for_each(|output| output.shift_left(2));

        let feed_count = self.feed_id - 2;
        let mut id_map = vec![0; feed_count];
        let mut next_id = 0;

        // Map input nodes starting from 0
        for input in &self.inputs {
            id_map[input.id()] = next_id;
            next_id += 1;
        }

        // Map output nodes so that they are at the end.
        let output_id_start = feed_count - self.outputs.len();
        for (new_id, output) in self.outputs.iter().enumerate() {
            id_map[output.id()] = output_id_start + new_id;
        }

        // Map all gate output nodes.
        self.gates.iter_mut().for_each(|gate| {
            match gate {
                Gate::And { z, .. }
                | Gate::Xor { z, .. }
                | Gate::Inv { z, .. }
                | Gate::Id { z, .. } => {
                    // If the ID is zero then this gate output is not in the
                    // last layer of the circuit. So we just
                    // give it the next available ID.
                    let id = if id_map[z.id()] == 0 {
                        let id = next_id;
                        id_map[z.id()] = id;
                        next_id += 1;
                        id
                    } else {
                        id_map[z.id()]
                    };

                    z.id = id;
                }
            }
        });

        // Remap all the input nodes of the gates.
        self.gates.iter_mut().for_each(|gate| {
            let (x, y) = match gate {
                Gate::And { x, y, .. } => (x, Some(y)),
                Gate::Xor { x, y, .. } => (x, Some(y)),
                Gate::Inv { x, .. } => (x, None),
                Gate::Id { x, .. } => (x, None),
            };

            x.id = id_map[x.id()];
            if let Some(y) = y {
                y.id = id_map[y.id()];
            }
        });

        // Wire IDs are now as follows:
        // inputs | intermediate outputs | outputs

        Ok(Circuit {
            inputs: 0..self.inputs.len(),
            outputs: feed_count - self.outputs.len()..feed_count,
            gates: self.gates,
            feed_count,
            and_count: self.and_count,
            xor_count: self.xor_count,
        })
    }
}
