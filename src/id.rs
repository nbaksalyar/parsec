// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// use ffi;
// use safe_crypto::{PublicKeys, SecretKeys, Signature as CryptoSignature};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::hash::Hash;

/// The public identity of a node.  It provides functionality to allow it to be used as an
/// asymmetric signing public key.
pub trait PublicId: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned + Debug {
    /// The signature type associated with the chosen asymmetric key scheme.
    type Signature: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned + Debug;

    /// Verifies `signature` against `data` using this `PublicId`.  Returns `true` if valid.
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool;
}

/// The secret identity of a node.  It provides functionality to allow it to be used as an
/// asymmetric signing secret key and to also yield the associated public identity.
pub trait SecretId {
    /// The associated public identity type.
    type PublicId: PublicId;

    /// Returns the associated public identity.
    fn public_id(&self) -> &Self::PublicId;

    /// Creates a detached `Signature` of `data`.
    fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as PublicId>::Signature;

    /// Creates a `Proof` of `data`.
    fn create_proof(&self, data: &[u8]) -> Proof<Self::PublicId> {
        Proof {
            public_id: self.public_id().clone(),
            signature: self.sign_detached(data),
        }
    }
}

// /// An object representing the signature of a `PublicKey`.
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
// pub struct Signature(CryptoSignature);

// impl Signature {
//     pub fn as_bytes(&self) -> &[u8] {
//         self.0.as_bytes()
//     }

//     /// Consumes the object and returns the wrapped raw pointer.
//     ///
//     /// You're now responsible for freeing this memory once you're done.
//     pub fn into_repr_c(self) -> *const ffi::Signature {
//         Box::into_raw(Box::new(ffi::Signature {
//             signature: Box::into_raw(Box::new(self)),
//         }))
//     }
// }

// impl ReprC for Signature {
//     type C = *const ffi::Signature;
//     type Error = ();

//     /// Constructs the object from a raw pointer.
//     ///
//     /// After calling this function, the raw pointer is owned by the resulting object.
//     #[allow(unsafe_code)]
//     unsafe fn clone_from_repr_c(c_repr: Self::C) -> Result<Self, Self::Error> {
//         // Get the native struct, extract from Box.
//         let native = Box::from_raw((*c_repr).signature as *mut _);
//         let signature = *native;

//         // Free the FFI struct.
//         let _ = Box::from_raw(c_repr as *mut _);

//         Ok(signature)
//     }
// }

// /// An object representing the public identity of a node. It is the default implementation of the
// /// `PublicId` trait.
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
// pub struct PublicKey(PublicKeys);

// impl PublicKey {
//     pub fn new() -> Self {
//         PublicKey(PublicKeys::new())
//     }
// }

// impl PublicId for PublicKey {
//     type Signature = Signature;

//     fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
//         self.0.verify_detached(&signature.0, data)
//     }
// }

// /// An object representing the secret identity of a node. It is the default implementation of the
// /// `SecretId` trait.
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct SecretKey(SecretKeys, PublicKey);

// impl SecretKey {
//     pub fn new() -> Self {
//         SecretKey(SecretKeys::new())
//     }
// }

// impl SecretId for SecretKey {
//     type PublicId = PublicKey;

//     fn public_id(&self) -> &Self::PublicId {
//         &self.1
//     }

//     fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as PublicId>::Signature {
//         Signature(self.0.sign_detached(data).clone())
//     }
// }

/// A basic helper to carry a given [`Signature`](trait.PublicId.html#associatedtype.Signature)
/// along with the signer's [`PublicId`](trait.PublicId.html).
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Proof<P: PublicId> {
    pub(super) public_id: P,
    pub(super) signature: P::Signature,
}

impl<P: PublicId> Proof<P> {
    /// Returns the associated public identity.
    pub fn public_id(&self) -> &P {
        &self.public_id
    }

    /// Returns the associated signature.
    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    /// Verifies this `Proof` against `data`.  Returns `true` if valid.
    pub fn is_valid(&self, data: &[u8]) -> bool {
        self.public_id.verify_signature(&self.signature, data)
    }
}
