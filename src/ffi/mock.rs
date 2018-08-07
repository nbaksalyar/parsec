// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi_utils::{self, ReprC};
use id::{PublicId, SecretId};
use maidsafe_utilities::SeededRng;
use mock::{
    self, PeerId as NativePeerId, Signature as NativeSignature, Transaction as NativeTransaction,
};
use rand::Rand;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;
use std::sync::Mutex;

// TODO: Make this thread-local instead?
lazy_static! {
    static ref RNG: Mutex<RefCell<SeededRng>> = { Mutex::new(RefCell::new(SeededRng::new())) };
}

#[no_mangle]
pub extern "C" fn rng_set(seed: [u32; 4]) -> i32 {
    let cell = unwrap!(RNG.lock());
    let _ = cell.replace(SeededRng::from_seed(seed));

    0
}

#[repr(C)]
pub struct Signature {
    pub signature: *const c_char,
}

impl Drop for Signature {
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.signature as *mut _);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn signature_new(
    data: *const c_char,
    o_signature: *mut *const Signature,
) -> i32 {
    let data = try_res!(ffi_utils::from_c_str(data).map_err(Error::from));
    let signature = NativeSignature::new(&data);
    let signature = try_res!(signature.into_repr_c());

    ffi_return_1!(o_signature, signature)
}

#[no_mangle]
pub unsafe extern "C" fn signature_free(signature: *const Signature) -> i32 {
    let _ = Box::from_raw(signature as *mut Signature);

    0
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[repr(C)]
pub struct PeerId {
    pub id: *const c_char,
}

impl Drop for PeerId {
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.id as *mut _);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn peer_id_new(id: *const c_char, o_peer_id: *mut *const PeerId) -> i32 {
    let id = try_res!(ffi_utils::from_c_str(id).map_err(Error::from));
    let peer_id = NativePeerId::new(&id);
    let peer_id = try_res!(peer_id.into_repr_c());

    ffi_return_1!(o_peer_id, peer_id)
}

#[no_mangle]
pub unsafe extern "C" fn peer_id_verify_signature(
    peer_id: *const PeerId,
    signature: *const Signature,
    data: *const u8,
    data_len: usize,
    o_status: *mut u8,
) -> i32 {
    let peer_id = try_res!(NativePeerId::clone_from_repr_c(peer_id));
    let signature = try_res!(NativeSignature::clone_from_repr_c(signature));
    let data = slice::from_raw_parts(data, data_len);

    let status = if peer_id.verify_signature(&signature, data) {
        1
    } else {
        0
    };

    *o_status = status;

    0
}

/// Returns the associated public identity.
#[no_mangle]
pub unsafe extern "C" fn peer_id_public_id(
    peer_id: *const PeerId,
    o_public_id: *mut *const c_char,
) -> i32 {
    *o_public_id = (*peer_id).id;

    0
}

/// Creates a detached `Signature` of `data`.
///
/// `o_signature` must be freed using `signature_free`.
#[no_mangle]
pub unsafe extern "C" fn peer_id_sign_detached(
    peer_id: *const PeerId,
    data: *const u8,
    data_len: usize,
    o_signature: *mut *const Signature,
) -> i32 {
    let peer_id = try_res!(NativePeerId::clone_from_repr_c(peer_id));
    let data = slice::from_raw_parts(data, data_len);

    let signature = peer_id.sign_detached(data);
    let signature = try_res!(signature.into_repr_c());

    ffi_return_1!(o_signature, signature)
}

#[no_mangle]
pub unsafe extern "C" fn peer_id_free(peer_id: *const PeerId) -> i32 {
    let _ = Box::from_raw(peer_id as *mut PeerId);

    0
}

#[repr(C)]
pub struct PeerIdList {
    pub peer_ids: *const PeerId,
    pub peer_ids_len: usize,
    pub peer_ids_cap: usize,
}

impl Drop for PeerIdList {
    fn drop(&mut self) {
        let _ = unsafe {
            Vec::from_raw_parts(
                self.peer_ids as *mut PeerId,
                self.peer_ids_len,
                self.peer_ids_cap,
            )
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn peer_id_list_get(
    peer_id_list: *const PeerIdList,
    index: usize,
    o_peer_id: *mut *const PeerId,
) -> i32 {
    let slice = slice::from_raw_parts((*peer_id_list).peer_ids, (*peer_id_list).peer_ids_len);

    // TODO: check if `index` is less than list length, return error if not

    *o_peer_id = &slice[index];

    0
}

#[no_mangle]
pub unsafe extern "C" fn peer_id_list_free(peer_id_list: *const PeerIdList) -> i32 {
    let _ = Box::from_raw(peer_id_list as *mut PeerIdList);

    0
}

/// **NOT FOR PRODUCTION USE**: Mock struct representing a network event.
#[repr(C)]
pub struct Transaction {
    pub transaction: *const c_char,
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.transaction as *mut _);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn transaction_new(
    id: *const c_char,
    o_transaction: *mut *const Transaction,
) -> i32 {
    let id = try_res!(ffi_utils::from_c_str(id).map_err(Error::from));
    let transaction = NativeTransaction::new(&id);
    let transaction = try_res!(transaction.into_repr_c());

    ffi_return_1!(o_transaction, transaction)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_rand(o_transaction: *mut *const Transaction) -> i32 {
    let mut cell = unwrap!(RNG.lock());
    let rng = cell.get_mut();
    let transaction = NativeTransaction::rand(rng);
    let transaction = try_res!(transaction.into_repr_c());

    ffi_return_1!(o_transaction, transaction)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_free(transaction: *const Transaction) -> i32 {
    let _ = Box::from_raw(transaction as *mut Transaction);

    0
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
///
/// `o_ids` must be freed using `peer_id_list_free`.
#[no_mangle]
pub unsafe extern "C" fn create_ids(count: usize, o_ids: *mut *const PeerIdList) -> i32 {
    let ids: Vec<PeerId> = try_res!(
        mock::create_ids(count)
            .into_iter()
            .map(|id| id.into_repr_c())
            .collect()
    );

    let (ptr, len, cap) = ffi_utils::vec_into_raw_parts(ids);
    let list = PeerIdList {
        peer_ids: ptr,
        peer_ids_len: len,
        peer_ids_cap: cap,
    };

    ffi_return_1!(o_ids, list)
}

#[no_mangle]
pub unsafe extern "C" fn names_len(o_len: *mut usize) -> i32 {
    *o_len = mock::names_len();

    0
}

#[cfg(test)]
mod tests {
    use ffi::mock::{self, PeerIdList};
    use ffi::utils;
    use ffi_utils::ReprC;
    use mock::Signature as NativeSignature;

    #[test]
    fn verify_signature() {
        let data = b"test";

        let ids: *const PeerIdList =
            unsafe { unwrap!(utils::get_1(|out| mock::create_ids(8, out))) };
        let id = unsafe { unwrap!(utils::get_1(|out| mock::peer_id_list_get(ids, 1, out))) };

        let signature = unsafe {
            unwrap!(utils::get_1(|out| mock::peer_id_sign_detached(
                id,
                data.as_ptr(),
                data.len(),
                out
            )))
        };

        // Check the signature is correct and doesn't get dropped by `clone_from_repr_c`.
        unsafe {
            let sig = unwrap!(NativeSignature::clone_from_repr_c(signature));
            assert_eq!(NativeSignature::new("of Bob"), sig);

            assert_eq!(
                NativeSignature::new("of Bob"),
                unwrap!(NativeSignature::clone_from_repr_c(signature))
            );
        }

        let result = unsafe {
            unwrap!(utils::get_1(|out| mock::peer_id_verify_signature(
                id,
                signature,
                data.as_ptr(),
                data.len(),
                out
            )))
        };
        assert_eq!(result, 1);

        // Check that the signature is still in memory up to this point.
        unsafe {
            assert_eq!(
                NativeSignature::new("of Bob"),
                unwrap!(NativeSignature::clone_from_repr_c(signature))
            );
        }

        // Free resources.
        unsafe {
            unwrap!(utils::get_0(|| mock::signature_free(signature)));
            unwrap!(utils::get_0(|| mock::peer_id_list_free(ids)));
        }
    }
}
