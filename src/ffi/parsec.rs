// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::Parsec as NativeParsec;

#[repr(C)]
pub struct Parsec {
    pub parsec: *const NativeParsec;
}

#[no_mangle]
pub extern "C" fn parsec_new(
    our_id: *const u8,
    genesis_group: *const *const u8,
    genesis_group_len: usize,
    o_parsec: *mut ParsecHandle,
) -> *const FfiResult {

}

#[no_mangle]
pub extern "C" fn parsec_vote_for(
    parsec: *const Parsec,
    network_event: *const u8,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_create_gossip(
    parsec: *const Parsec,
    peer_id: *const u8,
    o_request: *mut *const Request,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_handle_request(
    parsec: *const Parsec,
    src: *const u8,
    req: *const Request,
    o_response: *mut *const Response,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_handle_response(
    parsec: *const Parsec,
    src: *const u8,
    resp: *const Response,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_poll(
    parsec: *const Parsec,
    o_block: *mut *const Block,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_have_voted_for(
    parsec: *const Parsec,
    network_event: *const u8,
    o_have_voted_for: *mut u8,
) -> i32 {
}

#[no_mangle]
pub extern "C" fn parsec_free(parsec: *const Parsec) -> *const FfiResult {
    let _ = Box::from_raw((*self).parsec as *mut _);
    let _ = Box::from_raw(parsec as *mut _);
}
