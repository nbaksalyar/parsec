// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils;
use parsec::ffi::mock::{self, PeerId, Transaction};
use parsec::ffi::{self, test_utils, Block, Parsec};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::ptr;

pub struct Peer {
    pub id: *const PeerId,
    pub parsec: *const Parsec,
    // The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<*const Block>,
}

impl Peer {
    pub fn new(id: *const PeerId, genesis_group: Vec<*const PeerId>) -> Self {
        let (group, group_len, group_cap) = ffi_utils::vec_into_raw_parts(genesis_group);
        let parsec = unsafe {
            unwrap!(test_utils::get_1(|out| ffi::parsec_new(
                id,
                genesis_group,
                genesis_group_len,
                out
            )))
        };

        Self {
            id,
            parsec,
            blocks: ptr::null(),
            blocks_len: 0,
        }
    }

    pub fn vote_for(&mut self, transaction: *const Transaction) -> bool {
        let voted_for = unsafe {
            unwrap!(test_utils::get_1(|out| ffi::parsec_have_voted_for(
                self.parsec,
                transaction,
                out
            )))
        };

        if !voted_for {
            unsafe {
                unwrap!(test_utils::get_0(|| ffi::parsec_vote_for(
                    self.parsec,
                    transaction
                )))
            };
            true
        } else {
            false
        }
    }

    pub fn poll(&mut self) {
        while let Some(block) =
            unsafe { unwrap!(test_utils::get_1(|out| ffi::parsec_poll(self.parsec))) }
        {
            self.blocks.push(block);
        }
    }

    // Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<*const Transaction> {
        self.blocks
            .iter()
            .map(|block| unsafe {
                unwrap!(test_utils::get_1(|out| ffi::block_payload(block, out)))
            })
            .collect()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        unsafe {
            unwrap!(test_utils::get_0(|| ffi::peer_id_free(self.id)));
            unwrap!(test_utils::get_0(|| ffi::parsec_free(self.parsec)));

            for block in self.blocks {
                unwrap!(test_utils::get_0(|| ffi::block_free(block)));
            }
        }
    }
}

// impl Debug for Peer {
//     fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
//         write!(formatter, "{:?}: Blocks: {:?}", self.id, self.blocks)
//     }
// }
