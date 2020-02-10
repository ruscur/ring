// Copyright 2015-2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::super::{N, PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN};
use crate::{
    arithmetic::{bigint, montgomery::Unencoded},
    bits, error,
    limb::LIMB_BYTES,
};
use alloc::boxed::Box;

/// An RSA Public Key.
#[derive(Debug)]
pub struct Key {
    n: PublicModulus,
    e: PublicExponent,
}

impl Key {
    pub(in crate::rsa) fn from_modulus_and_exponent(
        n: untrusted::Input,
        e: untrusted::Input,
        n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength,
        e_min_value: u64,
    ) -> Result<Self, error::KeyRejected> {
        // This is an incomplete implementation of NIST SP800-56Br1 Section
        // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers
        // to NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key
        // Validation for RSA," "with the caveat that the length of the modulus
        // shall be a length that is specified in this Recommendation." In
        // SP800-89, two different sets of steps are given, one set numbered,
        // and one set lettered. TODO: Document this in the end-user
        // documentation for RSA keys.

        let n = PublicModulus::new(n, n_min_bits, n_max_bits)?;

        // If `n` is less than `e` then somebody has probably accidentally swapped
        // them. The largest acceptable `e` is smaller than the smallest acceptable
        // `n`, so no additional checks need to be done.
        let e = PublicExponent::new(e, e_min_value)?;

        // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
        // case in most other commonly-used crypto libraries.

        Ok(Self { n, e })
    }

    /// The public modulus.
    #[inline]
    pub fn n(&self) -> &PublicModulus {
        &self.n
    }

    /// The public exponent.
    #[inline]
    pub fn e(&self) -> &PublicExponent {
        &self.e
    }

    pub(in crate::rsa) fn exponentiate<'in_out>(
        &self,
        input: untrusted::Input,
        out_buffer: &'in_out mut [u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN], // TODO: clean this up
    ) -> Result<&'in_out [u8], error::Unspecified> {
        let n = &self.n.value;
        let n_bits = self.n.bits;
        let e = self.e.0;

        // The signature must be the same length as the modulus, in bytes.
        if input.len() != self.n.len_bits().as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        // RFC 8017 Section 5.2.2: RSAVP1.

        // Step 1.
        let s = bigint::Elem::from_be_bytes_padded(input, n)?;
        if s.is_zero() {
            return Err(error::Unspecified);
        }

        // Step 2.
        let m = bigint::elem_exp_vartime(s, e, n);
        let m = m.into_unencoded(n);

        // Step 3.
        Ok(fill_be_bytes_n(m, n_bits, out_buffer))
    }
}

/// Returns the big-endian representation of `elem` that is
/// the same length as the minimal-length big-endian representation of
/// the modulus `n`.
///
/// `n_bits` must be the bit length of the public modulus `n`.
fn fill_be_bytes_n(
    elem: bigint::Elem<N, Unencoded>,
    n_bits: bits::BitLength,
    out: &mut [u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN],
) -> &[u8] {
    let n_bytes = n_bits.as_usize_bytes_rounded_up();
    let n_bytes_padded = ((n_bytes + (LIMB_BYTES - 1)) / LIMB_BYTES) * LIMB_BYTES;
    let out = &mut out[..n_bytes_padded];
    elem.fill_be_bytes(out);
    let (padding, out) = out.split_at(n_bytes_padded - n_bytes);
    assert!(padding.iter().all(|&b| b == 0));
    out
}

pub struct PublicModulus {
    pub(in crate::rsa) value: bigint::Modulus<N>,
    bits: bits::BitLength,
}

impl core::fmt::Debug for PublicModulus {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        self.value.fmt(fmt)
    }
}

impl PublicModulus {
    fn new(
        n: untrusted::Input,
        min_bits: bits::BitLength,
        max_bits: bits::BitLength,
    ) -> Result<Self, error::KeyRejected> {
        // `pkcs1_encode` depends on this not being small. Otherwise,
        // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
        // bytes) for very small keys.
        const MIN_BITS: bits::BitLength = bits::BitLength::from_usize_bits(1024);

        // Step 3 / Step c for `n` (out of order).
        let (value, bits) = bigint::Modulus::from_be_bytes_with_bit_length(n)?;

        // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
        // the public modulus to be exactly 2048 or 3072 bits, but we are more
        // flexible to be compatible with other commonly-used crypto libraries.
        assert!(min_bits >= MIN_BITS);
        let bits_rounded_up =
            bits::BitLength::from_usize_bytes(bits.as_usize_bytes_rounded_up())
                .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
        if bits_rounded_up < min_bits {
            return Err(error::KeyRejected::too_small());
        }
        if bits > max_bits {
            return Err(error::KeyRejected::too_large());
        }

        Ok(Self { value, bits })
    }

    #[inline]
    pub(crate) fn len_bits(&self) -> bits::BitLength {
        self.bits
    }

    /// The length of the modulus in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bits.as_usize_bytes_rounded_up()
    }

    /// Returns the big-endian serislization of the modulus's value.
    #[inline]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        self.value.to_be_bytes()
    }
}

pub struct PublicExponent(pub(in crate::rsa) bigint::PublicExponent);

impl PublicExponent {
    fn new(e: untrusted::Input, e_min_value: u64) -> Result<Self, error::KeyRejected> {
        // XXX: FIPS 186-4 seems to indicate that the minimum
        // exponent value is 2**16 + 1, but it isn't clear if this is just for
        // signing or also for verification. We support exponents of 3 and larger
        // for compatibility with other commonly-used crypto libraries.

        // Step 2 / Step b.
        // Step 3 / Step c for `e`.
        Ok(Self(bigint::PublicExponent::from_be_bytes(e, e_min_value)?))
    }

    #[inline]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Debug for PublicExponent {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        self.0.fmt(fmt)
    }
}
