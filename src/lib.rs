// Hash256VarCore implementations are copy pasta of
// https://github.com/RustCrypto/hashes/blob/53d9671baf76133cd729ab9be37338ff2c50d973/sha2/src/core_api.rs
// Subject to the MIT license:
//
// Copyright (c) 2006-2009 Graydon Hoare
// Copyright (c) 2009-2013 Mozilla Foundation
// Copyright (c) 2016 Artyom Pavlov
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use digest::core_api::{
    AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
    CtVariableCoreWrapper, TruncSide, UpdateCore, VariableOutputCore,
};
use digest::typenum::{U32, U64};
use digest::{Digest, FixedOutput, HashMarker, InvalidOutputSize, Output, OutputSizeUser};
use sha2::{Sha256, Sha256VarCore};
use std::fmt;

/// A `Digest` implementation that performs Bitcoin style double-sha256
pub type DoubleHash256 = CoreWrapper<CtVariableCoreWrapper<DoubleHash256VarCore, U32>>;

#[derive(Clone)]
pub struct DoubleHash256VarCore(Sha256VarCore);

impl HashMarker for DoubleHash256VarCore {}

impl BlockSizeUser for DoubleHash256VarCore {
    type BlockSize = U64;
}

impl BufferKindUser for DoubleHash256VarCore {
    type BufferKind = <Sha256VarCore as BufferKindUser>::BufferKind;
}

impl UpdateCore for DoubleHash256VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        Sha256VarCore::update_blocks(&mut self.0, blocks);
    }
}

impl OutputSizeUser for DoubleHash256VarCore {
    type OutputSize = U32;
}

impl VariableOutputCore for DoubleHash256VarCore {
    const TRUNC_SIDE: TruncSide = Sha256VarCore::TRUNC_SIDE;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        Ok(Self(Sha256VarCore::new(output_size)?))
    }

    /// Perform double hash on finalization
    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        Sha256VarCore::finalize_variable_core(&mut self.0, buffer, out);
        let double_hash = Sha256::new_with_prefix(*out);
        FixedOutput::finalize_into(double_hash, out);
    }
}

impl AlgorithmName for DoubleHash256VarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Sha256VarCore::write_alg_name(f)
    }
}

impl fmt::Debug for DoubleHash256VarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash256VarCore { ... }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::signature::{DigestSigner, DigestVerifier};
    use k256::ecdsa::{Signature, SigningKey};
    use k256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn double_hash_is_same_as_sha256_twice() {
        let message = "hello world";

        let double_hasher = DoubleHash256::new_with_prefix(message.as_bytes());
        let double_hash = double_hasher.finalize();

        let hasher_one = Sha256::new_with_prefix(message.as_bytes());
        let hash_one = hasher_one.finalize();
        let hasher_two = Sha256::new_with_prefix(hash_one);
        let hash_two = hasher_two.finalize();

        assert_eq!(double_hash, hash_two);
    }

    #[test]
    fn verifies_signature_with_digest() -> Result<()> {
        let message = "hello world";

        let double_hasher = DoubleHash256::new_with_prefix(message.as_bytes());
        let signing_key = SigningKey::random(&mut OsRng);
        let sig: Signature = signing_key.try_sign_digest(double_hasher)?;

        let verifying_key = signing_key.verifying_key();
        let double_hasher = DoubleHash256::new_with_prefix(message.as_bytes());
        verifying_key.verify_digest(double_hasher, &sig)?;

        Ok(())
    }
}
