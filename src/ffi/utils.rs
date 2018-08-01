// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utils.

use std::mem;
use ffi_utils::FfiResult;

#[macro_export]
macro_rules! try_res {
    ($result:expr) => {{
        use ::ffi_utils::FfiResult;

        match $result {
            Ok(value) => value,
            e @ Err(_) => {
                let (error_code, description) = ffi_result!(e);
                return &FfiResult {
                    error_code,
                    description: description.as_ptr(),
                };
            }
        }
    }};
}

// Helper macro that sets the output value and ensures the value is not dropped.
#[macro_export]
macro_rules! ffi_return_1 {
    ($o_output:ident, $var:ident) => {{
        use ::ffi_utils::FFI_RESULT_OK;

        let _out = Box::new($var);
        *$o_output = Box::leak(_out);
        FFI_RESULT_OK
    }};
}

/// Runs an FFI function that contains zero output parameters and returns an i32 error code on
/// failure
pub unsafe fn get_0<F>(f: F) -> Result<(), i32>
where
    F: FnOnce() -> *const FfiResult,
{
    let res = f();

    if (*res).error_code == 0 {
        Ok(())
    } else {
        Err((*res).error_code)
    }
}

/// Runs an FFI function that contains one output parameter and returns either the output parameter
/// on success or an i32 error code on failure.
pub unsafe fn get_1<F, T>(f: F) -> Result<T, i32>
where
    F: FnOnce(*mut T) -> *const FfiResult,
{
    let mut output: T = mem::uninitialized();

    let res = f(&mut output);

    if (*res).error_code == 0 {
        Ok(output)
    } else {
        Err((*res).error_code)
    }
}
