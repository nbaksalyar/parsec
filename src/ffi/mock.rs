// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina",
];

#[no_mangle]
pub extern "C" fn rng_set(seed: [u32; 4]) -> *const FfiResult {}

/// **NOT FOR PRODUCTION USE**: Mock signature type.
#[repr(C)]
pub struct Signature {
    pub signature: *const u8,
}

#[no_mangle]
pub extern "C" fn signature_free(signature: *const Signature) -> *const FfiResult {}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[repr(C)]
pub struct PeerId {
    pub id: *const u8,
}

#[no_mangle]
pub extern "C" fn peer_id_new(id: *const u8, o_peer_id: *mut *const PeerId) -> *const FfiResult {}

#[no_mangle]
pub extern "C" fn peer_id_verify_signature(
    peer_id: *const PeerId,
    signature: *const u8,
    data: *const u8,
    o_status: *mut u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn peer_id_public_id(
    peer_id: *const PeerId,
    o_public_id: *mut *const u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn peer_id_sign_detached(
    peer_id: *const PeerId,
    data: *const u8,
    o_signature: *mut *const Signature,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn peer_id_free(peer_id: *const PeerId) -> *const FfiResult {}

/// **NOT FOR PRODUCTION USE**: Mock struct representing a network event.
#[repr(C)]
pub struct Transaction {
    pub transaction: *const u8,
}

#[no_mangle]
pub extern "C" fn transaction_new(
    id: *const u8,
    o_transaction: *mut *const Transaction,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn transaction_rand(o_transaction: *mut *const Transaction) -> *const FfiResult {}

#[no_mangle]
pub extern "C" fn transaction_free(transaction: *const Transaction) -> *const FfiResult {}

#[no_mangle]
pub extern "C" fn create_ids(
    count: usize,
    o_ids: *mut *const *const PeerId,
    o_ids_len: *mut usize,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn names_len(o_len: *mut usize) -> *const FfiResult {}

#[cfg(test)]
mod tests {
    use ffi::{mock, test_utils};

    #[test]
    fn verify_signature() {
        let data = b"test";

        let ids: Vec<*const PeerId> = unsafe {
            unwrap!(test_utils::get_vec(|out, out_len| mock::create_ids(
                8, out, out_len
            )))
        };
        let id = ids[0];

        let signature = unsafe {
            unwrap!(test_utils::get_1(|out| mock::peer_id_sign_detached(
                id, &data, out
            )))
        };

        let result = unsafe {
            unwrap!(test_utils::get_1(|out| mock::peer_id_verify_signature(
                id, signature, &data, out
            )))
        };
        assert_eq!(result, 1);

        // Free resources.
        unsafe {
            unwrap!(test_utils::get_0(|| mock::signature_free(signature)));

            for id in ids {
                unwrap!(test_utils::get_0(|| mock::peer_id_free(id)));
            }
        }
    }
}
