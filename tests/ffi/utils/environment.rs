// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::SeededRng;
use parsec::ffi::mock::{self, Transaction};
use rand::Rng;
use utils::Network;

pub struct PeerCount(pub usize);
pub struct TransactionCount(pub usize);

pub struct Environment {
    pub network: Network,
    pub transactions: Vec<*const Transaction>,
    pub rng: SeededRng,
}

impl Environment {
    /// Initialise the test environment with the given number of peers and transactions.  The random
    /// number generator will be seeded with `seed` or randomly if this is `None`.
    pub fn new(
        peer_count: &PeerCount,
        transaction_count: &TransactionCount,
        seed: Option<[u32; 4]>,
    ) -> Self {
        let network = Network::new(peer_count.0);

        if let Some(seed) = seed {
            // Set global RNG state using `rng`, to be used by `transaction_rand`.
            unsafe { unwrap!(test_utils::get_0(|| mock::rng_set(seed))) }
        };

        let transactions = (0..transaction_count.0)
            .map(|_| unsafe { unwrap!(test_utils::get_1(|out| mock::transaction_rand(out))) })
            .collect::<Vec<*const Transaction>>();

        Self {
            network,
            transactions,
            rng,
        }
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        for block in self.blocks {
            unsafe {
                unwrap!(test_utils::get_0(|| mock::transaction_free(block)));
            }
        }
    }
}
