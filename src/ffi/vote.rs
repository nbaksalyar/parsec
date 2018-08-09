// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::id::Proof;
use ffi::{utils, NetworkEvent, PeerId, SecretId, PublicId};
use std::slice;
use vote::Vote as NativeVote;

/// Serves as an opaque pointer to `Vote` struct.
pub struct Vote(NativeVote<NetworkEvent, PeerId>);

#[no_mangle]
pub unsafe extern "C" fn vote_new(
    secret_id: *const SecretId,
    payload: *const u8,
    payload_len: usize,
    o_vote: *mut *const Vote,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let payload_vec = slice::from_raw_parts(payload, payload_len).to_vec();
        let native_vote = NativeVote::new(&(*secret_id).0, payload_vec)?;

        *o_vote = Box::into_raw(Box::new(Vote(native_vote)));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn vote_payload(
    vote: *const Vote,
    o_payload: *mut *const u8,
    o_payload_len: *mut usize,
) -> i32 {
    let payload = (*vote).0.payload();

    *o_payload = payload.as_ptr();
    *o_payload_len = payload.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn vote_signature(
    vote: *const Vote,
    o_signature: *mut *const u8,
    o_signature_len: *mut usize,
) -> i32 {
    let signature = (*vote).0.signature();

    *o_signature = signature.as_ptr();
    *o_signature_len = signature.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn vote_is_valid(
    vote: *const Vote,
    public_id: *const PublicId,
    o_is_valid: *mut u8,
) -> i32 {
    if (*vote).0.is_valid(&(*public_id).0) {
        *o_is_valid = 1
    } else {
        *o_is_valid = 0
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn vote_create_proof(
    vote: *const Vote,
    public_id: *const PublicId,
    o_proof: *mut *const Proof,
) -> i32 {
    let native_proof = (*vote).0.create_proof(&(*public_id).0);

    *o_proof = Box::into_raw(Box::new(Proof(native_proof)));
    0
}

#[no_mangle]
pub unsafe extern "C" fn vote_free(vote: *const Vote) -> i32 {
    let _ = Box::from_raw(vote as *mut Vote);
    0
}
