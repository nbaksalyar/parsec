// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utils.

use error::Error;
use ffi::error;
use ffi_utils::{self, ErrorCode};
use std::fmt::{Debug, Display};
use std::panic::{self, AssertUnwindSafe};

// #[macro_export]
// macro_rules! try_res {
//     ($result:expr) => {{
//         use $crate::ffi::error;
//         match $result {
//             Ok(value) => value,
//             e @ Err(_) => {
//                 let (error_code, description) = ffi_result!(e);
//                 error::err_set(error_code, description);

//                 return error_code;
//             }
//         }
//     }};
// }

// // Helper macro that sets the output value and ensures the value is not dropped.
// #[macro_export]
// macro_rules! ffi_return_1 {
//     ($o_output:ident, $var:ident) => {{
//         let _out = Box::new($var);
//         *$o_output = Box::leak(_out);
//     }};
// }

/// Catches panics. On error sets the thread-local error message and returns the `i32` error code.
pub fn catch_unwind_err_set<'a, F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), Error>,
{
    match ffi_utils::catch_unwind_result(f) {
        Err(err) => {
            let (error_code, description) = ffi_result!(Err::<(), Error>(err));
            error::err_set(error_code, description);
            error_code
        }
        Ok(()) => 0,
    }
}

/// Runs an FFI function that contains zero output parameters and returns an `i32` error code on
/// failure.
pub unsafe fn get_0<F>(f: F) -> Result<(), i32>
where
    F: FnOnce() -> i32,
{
    let res = f();

    if res == 0 {
        Ok(())
    } else {
        Err(res)
    }
}

/// Runs an FFI function that contains one output parameter and returns either the output parameter
/// on success or an `i32` error code on failure.
pub unsafe fn get_1<F, T>(f: F) -> Result<T, i32>
where
    F: FnOnce(*mut T) -> i32,
{
    use std::mem;

    let mut output: T = mem::uninitialized();
    let res = f(&mut output);

    if res == 0 {
        Ok(output)
    } else {
        Err(res)
    }
}
