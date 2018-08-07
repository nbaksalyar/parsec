// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils::{self, FFI_RESULT_OK};
use id::{
    PublicKey as NativePublicKey, SecretKey as NativeSecretKey, Signature as NativeSignature,
};
use std::slice;

#[repr(C)]
pub struct Signature {
    pub signature: *const NativeSignature,
}

#[no_mangle]
pub extern "C" fn signature_as_bytes(
    signature: *const Signature,
    o_bytes: *const u8,
    o_bytes_len: usize,
) -> i32 {

}

#[no_mangle]
pub extern "C" fn signature_free(signature: *const Signature) -> i32 {
    let _ = Box::from_raw((*self).signature as *mut _);
    let _ = Box::from_raw(signature as *mut _);
}

#[repr(C)]
pub struct PublicKey {
    pub id: *const NativePublicKey,
}

/// Verifies `signature` against `data` using this `public_key`. Returns `1` if valid.
#[no_mangle]
pub extern "C" fn public_key_verify_signature(
    public_key: *const PublicKey,
    signature: *const Signature,
    data: *const u8,
    data_len: usize,
    o_status: *mut u8,
) -> i32 {

}

#[no_mangle]
pub extern "C" fn public_key_free(public_key: *const PublicKey) -> i32 {
    let _ = Box::from_raw((*self).id as *mut _);
    let _ = Box::from_raw(public_key as *mut _);
}

#[repr(C)]
pub struct SecretKey {
    pub id: *const SecretKey,
}

/// Creates a new `SecretKey`.
///
/// `o_secret_key` must be freed using `secret_key_free`.
#[no_mangle]
pub extern "C" fn secret_key_new(o_secret_key: *mut *const SecretKey) -> i32 {
    let secret_key = NativeSecretKey::new();
    let secret_key = secret_key.into_repr_c();

    ffi_return_1!(o_secret_key, secret_key)
}

/// Returns the associated `PublicKey`.
///
/// `o_public_key` must be freed using `public_key_free`.
#[no_mangle]
pub extern "C" fn secret_key_public_key(
    secret_key: *const SecretKey,
    o_public_key: *mut *const PublicKey,
) -> i32 {

}

#[no_mangle]
pub extern "C" fn secret_key_sign_detached(
    secret_key: *const SecretKey,
    data: *const u8,
    data_len: usize,
    o_signature: *mut *const Signature,
) -> i32 {

}

#[no_mangle]
pub extern "C" fn secret_key_free(secret_key: *const SecretKey) -> i32 {
    let _ = Box::from_raw((*self).id as *mut _);
    let _ = Box::from_raw(secret_key as *mut _);
}

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
pub extern "C" fn proof_free(proof: *const Proof) -> *const FfiResult {}

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
