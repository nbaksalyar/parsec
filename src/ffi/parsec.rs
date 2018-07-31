// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub type ParsecHandle = u64;

// #[repr(C)]
// pub struct Parsec {
//     pub peer_manager: *const PeerManager,

//     pub events_hash: *const Hash,
//     pub events_event: *const Event,
//     pub events_len: usize,

//     pub events_order: *const HashList,

//     pub events_with_valid_blocks_public_id: *const *const u8,
//     pub events_with_valid_blocks_hash_queue: *const HashList,
//     pub events_with_valid_blocks_len: usize,

//     pub consensused_blocks: *const Block,
//     pub consensused_blocks_len: usize,

//     pub consensus_history: *const HashList,

//     pub meta_votes_hash: *const Hash,
//     pub meta_votes_vote_map: *const MetaVoteMap,
//     pub meta_votes_len: usize,

//     pub round_hashes_public_id: *const *const u8,
//     pub round_hashes_round_hash_list: *const RoundHashList,
//     pub round_hashes_len: usize,

//     pub responsiveness_threshold: usize,
// }

// /// Wrapper struct for some `Parsec` internal data.
// #[repr(C)]
// struct HashList {
//     hashes: *const Hash,
//     hashes_len: usize,
// }

// /// Wrapper struct for some `Parsec` internal data.
// #[repr(C)]
// struct MetaVoteMap {
//     public_ids: *const *const u8,
//     meta_vote_lists: *const MetaVoteList,
//     len: usize,
// }

// #[repr(C)]
// struct MetaVoteList {
//     meta_votes: *const MetaVote,
//     meta_votes_len: usize,
// }

// #[repr(C)]
// struct RoundHashList {
//     round_hashes: *const RoundHash,
//     round_hashes_len: usize,
// }

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
    parsec: ParsecHandle,
    network_event: *const u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_create_gossip(
    parsec: ParsecHandle,
    peer_id: *const u8,
    o_request: *mut *const Request,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_handle_request(
    parsec: ParsecHandle,
    src: *const u8,
    req: *const Request,
    o_response: *mut *const Response,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_handle_response(
    parsec: ParsecHandle,
    src: *const u8,
    resp: *const Response,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_poll(
    parsec: ParsecHandle,
    o_block: *mut *const Block,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_have_voted_for(
    parsec: ParsecHandle,
    network_event: *const u8,
    o_have_voted_for: *mut u8,
) -> *const FfiResult {
}

#[no_mangle]
pub extern "C" fn parsec_free(parsec: ParsecHandle) -> *const FfiResult {}
