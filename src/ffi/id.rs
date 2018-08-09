// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{PublicId, SecretId};
use error::Error;
use ffi::utils::catch_unwind_err_set;
use ffi_utils::{FfiResult, FFI_RESULT_OK};
use mock::PeerId;
use rand::Rng;
use std::{mem, slice, str};

#[repr(C)]
pub struct Signature;

// #[no_mangle]
// pub extern "C" fn signature_as_bytes(
//     signature: *const Signature,
//     o_bytes: *const u8,
//     o_bytes_len: usize,
// ) -> i32 {
//     0
// }

#[no_mangle]
pub extern "C" fn signature_free(signature: *const Signature) -> i32 {
    // let _ = Box::from_raw((*self).signature as *mut _);
    // let _ = Box::from_raw(signature as *mut _);
    0
}

// /// Verifies `signature` against `data` using this `public_key`. Returns `1` if valid.
// #[no_mangle]
// pub extern "C" fn public_id_verify_signature(
//     public_key: *const PublicId,
//     signature: *const Signature,
//     data: *const u8,
//     data_len: usize,
//     o_status: *mut u8,
// ) -> i32 {
//     0
// }

#[no_mangle]
pub unsafe extern "C" fn public_id_from_bytes(
    id: *const u8,
    id_len: usize,
    o_public_id: *mut *const PublicId,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let public_id = slice::from_raw_parts(id, id_len);
        let peer_id = PeerId::new(str::from_utf8(public_id)?);

        *o_public_id = Box::into_raw(Box::new(PublicId(peer_id)));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn public_id_free(public_id: *const PublicId) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(public_id as *mut PublicId);
        Ok(())
    })
}

/// Creates a new `SecretId`.
///
/// `o_secret_key` must be freed using `secret_key_free`.
#[no_mangle]
pub unsafe extern "C" fn secret_id_new(o_secret: *mut *const SecretId) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let secret = SecretId(PeerId::new("abc")); // rand
        *o_secret = &secret;
        mem::forget(secret);
        Ok(())
    })
}

/// Returns the associated `PublicId`.
///
/// `o_public_key` must be freed using `public_key_free`.
#[no_mangle]
pub unsafe extern "C" fn secret_id_public(
    secret_key: *const SecretId,
    o_public_key: *mut *const PublicId,
) -> i32 {
    0
}

// #[no_mangle]
// pub unsafe extern "C" fn secret_id_sign_detached(
//     secret_key: *const SecretId,
//     data: *const u8,
//     data_len: usize,
//     o_signature: *mut *const Signature,
// ) -> i32 {
//     0
// }

#[no_mangle]
pub unsafe extern "C" fn secret_id_from_bytes(
    id: *const u8,
    id_len: usize,
    o_secret_id: *mut *const SecretId,
) -> i32 {
    catch_unwind_err_set(|| -> Result<(), Error> {
        let public_id = slice::from_raw_parts(id, id_len);
        let peer_id = PeerId::new(str::from_utf8(public_id)?);

        *o_secret_id = Box::into_raw(Box::new(SecretId(peer_id)));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn secret_id_free(secret_id: *const SecretId) -> i32 {
    // let _ = Box::from_raw((*self).id as *mut _);
    let _ = Box::from_raw(secret_id as *mut SecretId);

    0
}

#[repr(C)]
pub struct Proof {
    pub public_id: *const u8,
    pub signature: *const u8,
}

#[no_mangle]
pub unsafe extern "C" fn proof_public_id(
    proof: *const Proof,
    o_public_id: *mut *const u8,
) -> *const FfiResult {
    FFI_RESULT_OK
}

#[no_mangle]
pub unsafe extern "C" fn proof_signature(
    proof: *const Proof,
    o_signature: *mut *const u8,
) -> *const FfiResult {
    FFI_RESULT_OK
}

#[no_mangle]
pub unsafe extern "C" fn proof_is_valid(
    proof: *const Proof,
    data: *const u8,
    o_is_valid: u8,
) -> *const FfiResult {
    FFI_RESULT_OK
}

#[no_mangle]
pub unsafe extern "C" fn proof_free(proof: *const Proof) -> *const FfiResult {
    FFI_RESULT_OK
}

#[repr(C)]
pub struct ProofList {
    pub proofs: *const Proof,
    pub proofs_len: usize,
}

#[no_mangle]
pub unsafe extern "C" fn proof_list_free(proof_list: *const ProofList) -> *const FfiResult {
    let slice = slice::from_raw_parts((*proof_list).proofs, (*proof_list).proofs_len);

    for proof in slice {
        let _ = proof_free(proof); // TODO: unused result
    }

    let _ = *proof_list;

    FFI_RESULT_OK
}
