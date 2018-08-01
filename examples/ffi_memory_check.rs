// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! An example allocating and freeing memory using the FFI API. Can be used in combination with
//! various tools to check for memory allocation problems. Requires nightly Rust.
//!
//! # Checking for memory leaks
//!
//! You can check for memory leaks using Valgrind. First build the example:
//!
//! ```
//! cargo build --example ffi_memory_check
//! ```
//!
//! Then run valgrind:
//!
//! ```
//! valgrind --leak-check=full target/debug/examples/ffi_memory_check
//! ```
//!
//! You should see a leak summary. The fields that concern us are "definitely lost" and "indirectly
//! lost": these should be 0. The other fields can be treated with suspicion -- "possibly lost"
//! seems to always report some bytes.
//!
//! # Running sanitizers
//!
//! Note: You will need to comment out the lines specifying the `System` allocator, which are
//! required for Valgrind but conflict with the sanitizers.
//!
//! You can run several different sanitizers using variations of the following command:
//!
//! ```
//! RUSTFLAGS="-Z sanitizer=address" cargo run --example ffi_memory_check --target x86_64-apple-darwin -- --nocapture
//! ```
//!
//! Possible targets are limited to:
//!
//! * x86_64-unknown-linux-gnu: supports the `address`, `leak`, `memory`, and `thread` sanitizers.
//! * x86_64-apple-darwin: supports the `address` and `thread` sanitizers.
//!
//! More information can be found at https://github.com/japaric/rust-san.

#![forbid(
    exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types, warnings
)]
#![deny(
    bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
    overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
    stable_features, unconditional_recursion, unknown_lints, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true
)]
#![warn(
    trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results
)]
#![allow(
    box_pointers, missing_copy_implementations, missing_debug_implementations, trivial_casts,
    variant_size_differences
)]
#![feature(global_allocator)]
#![feature(allocator_api)]

extern crate ffi_utils;
extern crate parsec;
extern crate rand;
#[macro_use]
extern crate unwrap;

// Use the system allocator for compatibility with Valgrind.
use std::alloc::System;
#[global_allocator]
static GLOBAL: System = System;

use ffi_utils::ReprC;
use parsec::ffi::{mock, utils};
use parsec::mock::{PeerId as NativePeerId, Signature as NativeSignature};
use std::ffi::CString;

fn main() {
    // Set the number of new/free iterations and the number of conversions for each object. The
    // total number of operations for each object is on the order of `NUM_ITERATIONS *
    // NUM_CONVERSIONS`.
    const NUM_ITERATIONS: usize = 100;
    const NUM_CONVERSIONS: usize = 100;

    // Stack variables

    for _ in 1..NUM_ITERATIONS {
        let len = unsafe { unwrap!(utils::get_1(|out| mock::names_len(out))) };
        assert_eq!(len, 20);
    }
    println!("Finished checking stack variables.");

    // PeerId

    for _ in 1..NUM_ITERATIONS {
        let random = generate_random_string(10);
        let random2 = random.clone();
        let random = unwrap!(CString::new(random));

        // Pass in `random` then drop it. The PeerId should have its own copy that it's
        // responsible for freeing.
        let ptr = unsafe { unwrap!(utils::get_1(|out| mock::peer_id_new(random.as_ptr(), out))) };
        drop(random);
        let mut native = unsafe { unwrap!(NativePeerId::clone_from_repr_c(ptr)) };

        for _ in 1..NUM_CONVERSIONS {
            let repr_c = unwrap!(native.into_repr_c());
            native = unsafe { unwrap!(NativePeerId::clone_from_repr_c(&repr_c)) };
        }

        assert_eq!(NativePeerId::new(&random2), native);

        unsafe { unwrap!(utils::get_0(|| mock::peer_id_free(ptr))); }
    }
    println!("Finished checking PeerId.");

    // PeerIdList

    for _ in 1..NUM_ITERATIONS {
        unsafe {
            let ids = unwrap!(utils::get_1(|out| mock::create_ids(8, out)));
            unwrap!(utils::get_0(|| mock::peer_id_list_free(ids)));
        }
    }
    println!("Finished checking PeerIdList.");

    // Signature

    for _ in 1..NUM_ITERATIONS {
        let random = generate_random_string(10);
        let random2 = random.clone();
        let random = unwrap!(CString::new(random));

        // Pass in `random` then drop it. The Signature should have its own copy that it's
        // responsible for freeing.
        let ptr = unsafe {
            unwrap!(utils::get_1(|out| mock::signature_new(
                random.as_ptr(),
                out
            )))
        };
        drop(random);
        let mut native = unsafe { unwrap!(NativeSignature::clone_from_repr_c(ptr)) };

        for _ in 1..NUM_CONVERSIONS {
            let repr_c = unwrap!(native.into_repr_c());
            native = unsafe { unwrap!(NativeSignature::clone_from_repr_c(&repr_c)) };
        }

        assert_eq!(NativeSignature::new(&random2), native);

        unsafe { unwrap!(utils::get_0(|| mock::signature_free(ptr))); }
    }
    println!("Finished checking Signature.");
}

/// Generates a random String of `length` characters.
fn generate_random_string(length: usize) -> String {
    use rand::Rng;

    let mut os_rng = unwrap!(::rand::OsRng::new());
    os_rng.gen_ascii_chars().take(length).collect()
}
