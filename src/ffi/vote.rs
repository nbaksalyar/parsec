// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[repr(C)]
pub struct Vote {
    pub payload: *const u8,
    pub signature: *const u8,
}

#[no_mangle]
pub extern "C" fn vote_new(
    secret_id: *const u8,
    payload: *const u8,
    o_vote: *mut *const Vote,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn vote_payload(vote: *const Vote, o_payload: *mut *const u8) -> *const FfiResult {}

#[no_mangle]
pub extern "C" fn vote_signature(
    vote: *const Vote,
    o_signature: *mut *const u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn vote_is_valid(
    vote: *const Vote,
    public_id: *const u8,
    o_is_valid: *mut u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn vote_create_proof(
    vote: *const Vote,
    public_id: *const u8,
    o_proof: *mut *const Proof,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn vote_free(vote: *const Vote) -> *const FfiResult {}
