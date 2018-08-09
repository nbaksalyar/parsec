// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Block FFI.

use block::Block as NativeBlock;
use error::Error;
use ffi::utils::catch_unwind_err_set;
use ffi::{NetworkEvent, PeerId, Proof, ProofList, PublicId, Vote};
use std::collections::BTreeMap;
use std::{mem, slice};

/// Block FFI object.
pub struct Block(pub(crate) NativeBlock<NetworkEvent, PeerId>);

/// Create a new block from `payload` and the `public_ids` with their corresponding `votes`.
/// `items_len` corresponds to a number of `votes` and `public_ids` which must be the same.
#[no_mangle]
pub unsafe extern "C" fn block_new(
    payload: *const u8,
    payload_len: usize,
    public_ids: *const *const PublicId,
    votes: *const *const Vote,
    items_len: usize,
    o_block: *mut *const Block,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let payload = slice::from_raw_parts(payload, payload_len).to_vec();
        let public_ids = slice::from_raw_parts(public_ids, items_len);
        let votes = slice::from_raw_parts(votes, items_len);

        let mut votes_map = BTreeMap::new();

        public_ids.iter().zip(votes.iter()).for_each(|(id, vote)| {
            let _ = votes_map.insert((**id).0.clone(), (**vote).0.clone());
        });

        let block = Box::new(Block(NativeBlock::new(payload, &votes_map)?));
        *o_block = Box::into_raw(block);

        Ok(())
    })
}

/// Returns the Payload of this block.
#[no_mangle]
pub unsafe extern "C" fn block_payload(
    block: *const Block,
    o_payload: *mut *const u8,
    o_payload_len: *mut usize,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let payload = (*block).0.payload();

        *o_payload = payload.as_ptr();
        *o_payload_len = payload.len();

        Ok(())
    })
}

/// Returns the Proofs of this block.
///
/// This block's Proofs should not be freed manually -- `block_free` takes care of that.
#[no_mangle]
pub unsafe extern "C" fn block_proofs(block: *const Block, o_proofs: *mut ProofList) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let proofs: Vec<_> = (*block)
            .0
            .proofs()
            .iter()
            .map(|proof| Box::into_raw(Box::new(Proof(proof.clone()))))
            .collect();

        *o_proofs = ProofList {
            proofs: proofs.as_ptr() as *const _,
            proofs_len: proofs.len(),
            proofs_cap: proofs.capacity(),
        };

        mem::forget(proofs);

        Ok(())
    })
}

/// Converts `vote` to a `Proof` and attempts to add it to the block. Returns an error if `vote` is
/// invalid (i.e. signature check fails or the `vote` is for a different network event). Sets
/// `o_new_proof` to `1` if the `Proof` wasn't previously held in this `Block`, or `0` if it was
/// previously held.
#[no_mangle]
pub unsafe extern "C" fn block_add_vote(
    block: *mut Block,
    peer_id: *const PublicId,
    vote: *const Vote,
    o_new_proof: *mut u8,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        *o_new_proof = (*block).0.add_vote(&(*peer_id).0, &(*vote).0)? as u8;
        Ok(())
    })
}

/// Frees this block and its associated data.
#[no_mangle]
pub unsafe extern "C" fn block_free(block: *mut Block) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(block);
        Ok(())
    })
}
