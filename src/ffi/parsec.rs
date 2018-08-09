// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::utils::catch_unwind_err_set;
use ffi::{Block, FfiResult, NetworkEvent, PeerId, PublicId, Request, Response, SecretId};
use ffi_utils::FFI_RESULT_OK;
use parsec::Parsec as NativeParsec;
use std::collections::BTreeSet;
use std::{mem, ptr, slice};

/// Serves as an opaque pointer to `Parsec` struct
pub struct Parsec(NativeParsec<NetworkEvent, PeerId>);

/// Returns an opaque pointer to the `Parsec` structure.
#[no_mangle]
pub unsafe extern "C" fn parsec_new(
    our_id: *const SecretId,
    genesis_group: *const *const PublicId,
    genesis_group_len: usize,
    o_parsec: *mut *mut Parsec,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let genesis_vec = slice::from_raw_parts(genesis_group, genesis_group_len);
        let genesis_group_set: BTreeSet<_> =
            genesis_vec.iter().map(|id| (**id).0.clone()).collect();

        let native_parsec = NativeParsec::new((*our_id).0.clone(), &genesis_group_set)?;
        let mut parsec = Box::new(Parsec(native_parsec));

        *o_parsec = Box::into_raw(parsec);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn parsec_vote_for(
    parsec: *mut Parsec,
    network_event: *const u8,
    network_event_len: usize,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let network_event = slice::from_raw_parts(network_event, network_event_len).to_vec();
        let _ = (*parsec).0.vote_for(network_event)?;
        Ok(())
    })
}

/// Returns an opaque `request`.
#[no_mangle]
pub unsafe extern "C" fn parsec_create_gossip(
    parsec: *const Parsec,
    peer_id: *const PublicId,
    o_request: *mut *const Request,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let peer = if peer_id.is_null() {
            None
        } else {
            Some((*peer_id).0.clone())
        };

        let req = (*parsec).0.create_gossip(peer)?;
        *o_request = Box::into_raw(Box::new(Request(req)));
        Ok(())
    })
}

/// Returns an opaque `response`.
#[no_mangle]
pub unsafe extern "C" fn parsec_handle_request(
    parsec: *mut Parsec,
    src: *const PublicId,
    req: *const Request,
    o_response: *mut *const Response,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let resp = (*parsec).0.handle_request(&(*src).0, (*req).0.clone())?;
        *o_response = Box::into_raw(Box::new(Response(resp)));
        Ok(())
    })
}

/// Handles an opaque response.
#[no_mangle]
pub unsafe extern "C" fn parsec_handle_response(
    parsec: *mut Parsec,
    src: *const PublicId,
    resp: *const Response,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let resp = (*parsec).0.handle_response(&(*src).0, (*resp).0.clone())?;
        Ok(())
    })
}

/// Steps the algorithm and returns the next stable block, if any.
#[no_mangle]
pub unsafe extern "C" fn parsec_poll(parsec: *mut Parsec, o_block: *mut *const Block) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let res = (*parsec).0.poll();

        *o_block = if let Some(block) = res {
            let block = Block(block);
            Box::into_raw(Box::new(block))
        } else {
            ptr::null()
        };
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn parsec_have_voted_for(
    parsec: *const Parsec,
    network_event: *const u8,
    network_event_len: usize,
    o_result: *mut u8,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let network_event = slice::from_raw_parts(network_event, network_event_len).to_vec();
        *o_result = (*parsec).0.have_voted_for(&network_event) as u8;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn parsec_free(parsec: *mut Parsec) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(parsec);
        Ok(())
    })
}
