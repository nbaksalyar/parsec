// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils::{FFI_RESULT_OK, self};
use std::slice;

#[repr(C)]
pub struct Proof {
    pub public_id: *const u8,
    pub signature: *const u8,
}

#[no_mangle]
pub extern "C" fn proof_public_id(
    proof: *const Proof,
    o_public_id: *mut *const u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn proof_signature(
    proof: *const Proof,
    o_signature: *mut *const u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn proof_is_valid(
    proof: *const Proof,
    data: *const u8,
    o_is_valid: u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn proof_free(proof: *const Proof) -> *const FfiResult {
}

#[repr(C)]
pub struct ProofList {
    pub proofs: *const *const Proof,
    pub proofs_len: usize,
}

#[no_mangle]
pub extern "C" fn proof_list_free(proof_list: *const ProofList) -> *const FfiResult {
    let slice = slice::from_raw_parts(*proof_list.proofs, *proof_list.proofs_len);

    for proof in slice {
        proof_free(proof);
    }

    drop(*proof_list);

    FFI_RESULT_OK
}
