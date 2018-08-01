// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! FFI.

#![allow(unsafe_code)]

#[macro_use]
pub mod utils;

#[doc(hidden)]
/// **NOT FOR PRODUCTION USE**: Mock types which trivially implement the required Parsec traits.
///
/// This can be used to swap proper cryptographic functionality for inexpensive (in some cases
/// no-op) replacements.  This is useful to allow tests to run quickly, but should not be used
/// outside of testing code.
pub mod mock;

// mod block;
// mod gossip;
// mod parsec;
// mod proof;
// mod vote;

// pub use block::*;
// pub use gossip::*;
// pub use parsec::*;
// pub use proof::*;
// pub use vote::*;

pub use ffi_utils::FfiResult;
