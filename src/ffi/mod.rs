// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! FFI.

// TODO: !!!
#![allow(unused)]
#![allow(missing_docs)]
#![allow(unsafe_code)]

#[macro_use]
pub mod utils;

pub mod block;
/// Functions for getting and clearing FFI errors.
pub mod error;
/// Functions defining public and private identity traits and objects.
pub mod id;
pub mod parsec;
pub mod vote;

use super::{Request as ParsecReq, Response as ParsecResp};
use mock;
use network_event::NetworkEvent as NetEvent;

pub(crate) type NetworkEvent = Vec<u8>;
pub(crate) type PeerId = mock::PeerId;

pub struct SecretId(PeerId);
pub struct PublicId(PeerId);

pub struct Request(ParsecReq<NetworkEvent, PeerId>);
pub struct Response(ParsecResp<NetworkEvent, PeerId>);

impl NetEvent for Vec<u8> {}

pub use ffi::block::*;
pub use ffi::error::*;
pub use ffi::id::*;
pub use ffi::parsec::*;
pub use ffi::vote::*;
pub use ffi_utils::FfiResult;
