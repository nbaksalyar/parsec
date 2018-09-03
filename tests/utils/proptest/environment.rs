// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use proptest::prelude::RngCore;
use proptest::strategy::{NewTree, Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use rand::{SeedableRng, XorShiftRng};
use utils::proptest::{Bounded, BoundedBoxedStrategy};
use utils::{
    Environment, Network, ParsecImpl, ParsecRustImpl, PeerCount, RngChoice, TransactionCount,
};

#[derive(Debug)]
pub struct EnvironmentStrategy {
    pub num_peers: BoundedBoxedStrategy<usize>,
    pub num_transactions: BoundedBoxedStrategy<usize>,
}

impl Default for EnvironmentStrategy {
    fn default() -> Self {
        EnvironmentStrategy {
            num_peers: (4..=10).into(),
            num_transactions: (1..10).into(),
        }
    }
}

pub struct EnvironmentValueTree<P: ParsecImpl> {
    max_env: Environment<P>,
    peers_trans: Box<ValueTree<Value = (usize, usize)>>,
    min_peers_trans: (usize, usize),
    seed: [u32; 4],
}

impl<P: ParsecImpl> EnvironmentValueTree<P> {
    fn filtered_environment(&self, n_peers: usize, n_trans: usize) -> Environment<P> {
        let peer_ids = self
            .max_env
            .network
            .peers
            .iter()
            .take(n_peers)
            .map(|p| p.id.clone());
        let network = Network::with_peers(peer_ids);
        let transactions = self
            .max_env
            .transactions
            .iter()
            .take(n_trans)
            .cloned()
            .collect();
        Environment {
            network,
            transactions,
            rng: Box::new(XorShiftRng::from_seed(self.seed)),
        }
    }
}

impl<P: ParsecImpl> Bounded for EnvironmentValueTree<P> {
    type Bound = Environment<P>;

    fn min(&self) -> Environment<P> {
        let (n_peers, n_trans) = self.min_peers_trans;
        self.filtered_environment(n_peers, n_trans)
    }

    fn max(&self) -> Environment<P> {
        let (n_peers, n_trans) = (
            self.max_env.network.peers.len(),
            self.max_env.transactions.len(),
        );
        self.filtered_environment(n_peers, n_trans)
    }
}

impl<P: ParsecImpl> ValueTree for EnvironmentValueTree<P> {
    type Value = Environment<P>;

    fn current(&self) -> Environment<P> {
        let (n_peers, n_trans) = self.peers_trans.current();
        self.filtered_environment(n_peers, n_trans)
    }

    fn simplify(&mut self) -> bool {
        self.peers_trans.simplify()
    }

    fn complicate(&mut self) -> bool {
        self.peers_trans.complicate()
    }
}

impl Strategy for EnvironmentStrategy {
    type Value = Environment<ParsecRustImpl>;
    type Tree = EnvironmentValueTree<ParsecRustImpl>;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        let seed = {
            let rng = runner.rng();
            [
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ]
        };
        let env = Environment::new(
            &PeerCount(self.num_peers.max()),
            &TransactionCount(self.num_transactions.max()),
            RngChoice::SeededXor(seed),
        );
        (&self.num_peers, &self.num_transactions)
            .new_tree(runner)
            .map(|t| EnvironmentValueTree {
                max_env: env,
                peers_trans: Box::new(t),
                min_peers_trans: (self.num_peers.min(), self.num_transactions.min()),
                seed,
            })
    }
}
