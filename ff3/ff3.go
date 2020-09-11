/*

SPDX-Copyright: Copyright (c) Capital One Services, LLC
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

*/

// Package ff3 implements the FF3 format-preserving encryption
// algorithm/scheme
package ff3

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
)

// Note that this is strictly following the official NIST guidelines. In the linked PDF Appendix A (README.md), NIST recommends that radix^minLength >= 1,000,000. If you would like to follow that, change this parameter.
const (
	feistelMin   = 100
	numRounds    = 8
	blockSize    = aes.BlockSize
	tweakLen     = 8
	halfTweakLen = tweakLen / 2
	// maxRadix   = 65536 // 2^16
)

var (
	// ErrStringNotInRadix is returned if input or intermediate strings cannot be parsed in the given radix
	ErrStringNotInRadix = errors.New("string is not within base/radix")

	// ErrTweakLengthInvalid is returned if the tweak length is not 8 bytes
	ErrTweakLengthInvalid = errors.New("tweak must be 8 bytes, or 64 bits")
)

// A Cipher is an instance of the FF3 mode of format preserving encryption
// using a particular key, radix, and tweak
type Cipher struct {
	tweak  []byte
	radix  int
	minLen uint32
	maxLen uint32

	// Re-usable AES block
	aesBlock cipher.Block
}

// NewCipher initializes a new FF3 Cipher for encryption or decryption use
// based on the radix, key and tweak parameters.
func NewCipher(radix int, key []byte, tweak []byte) (Cipher, error) {
	var newCipher Cipher

	keyLen := len(key)

	// Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
	if (keyLen != 16) && (keyLen != 24) && (keyLen != 32) {
		return newCipher, errors.New("key length must be 128, 192, or 256 bits")
	}

	// While FF3 allows radices in [2, 2^16], there is a practical limit to 36 (alphanumeric) because the Go math/big library only supports up to base 36.
	if (radix < 2) || (radix > big.MaxBase) {
		return newCipher, errors.New("radix must be between 2 and 36, inclusive")
	}

	// Make sure the given the length of tweak in bits is 64
	if len(tweak) != tweakLen {
		return newCipher, ErrTweakLengthInvalid
	}

	// Calculate minLength - according to the spec, radix^minLength >= 100.
	minLen := uint32(math.Ceil(math.Log(feistelMin) / math.Log(float64(radix))))

	maxLen := uint32(math.Floor((192 / math.Log2(float64(radix)))))

	// Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
	if (minLen < 2) || (maxLen < minLen) || (float64(maxLen) > (192 / math.Log2(float64(radix)))) {
		return newCipher, errors.New("minLen or maxLen invalid, adjust your radix")
	}

	// aes.NewCipher automatically returns the correct block based on the length of the key passed in
	// Always use the reversed key since Encrypt and Decrypt call ciph expecting that
	aesBlock, err := aes.NewCipher(revB(key))
	if err != nil {
		return newCipher, errors.New("failed to create AES block")
	}

	newCipher.tweak = tweak
	newCipher.radix = radix
	newCipher.minLen = minLen
	newCipher.maxLen = maxLen
	newCipher.aesBlock = aesBlock

	return newCipher, nil
}

// Encrypt encrypts the string X over the current FF3 parameters
// and returns the ciphertext of the same length and format
func (c Cipher) Encrypt(X string) (string, error) {
	return c.EncryptWithTweak(X, c.tweak)
}

// EncryptWithTweak is the same as Encrypt except it uses the
// tweak from the parameter rather than the current Cipher's tweak
// This allows you to re-use a single Cipher (for a given key) and simply
// override the tweak for each unique data input, which is a practical
// use-case of FPE for things like credit card numbers.
func (c Cipher) EncryptWithTweak(X string, tweak []byte) (string, error) {
	var ret string
	var ok bool

	n := uint32(len(X))

	// Check if message length is within minLength and maxLength bounds
	// TODO BUG: when n==c.maxLen, it breaks. For now, I'm changing
	// the input check to >= instead of only >
	if (n < c.minLen) || (n >= c.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	// Make sure the given the length of tweak in bits is 64
	if len(tweak) != tweakLen {
		return ret, ErrTweakLengthInvalid
	}

	radix := c.radix

	// Check if the message is in the current radix
	var numX big.Int
	_, ok = numX.SetString(X, radix)
	if !ok {
		return ret, ErrStringNotInRadix
	}

	// Calculate split point
	u := uint32(math.Ceil(float64(n) / 2))
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Split the tweak
	Tl := tweak[:halfTweakLen]
	Tr := tweak[halfTweakLen:]

	// P is always 16 bytes
	var (
		P = make([]byte, blockSize)
		m uint32
		W []byte

		numB, numC       big.Int
		numRadix, numY   big.Int
		numU, numV       big.Int
		numModU, numModV big.Int
		S, numBBytes     []byte
	)

	numRadix.SetInt64(int64(radix))

	// Pre-calculate the modulus since it's only one of 2 values,
	// depending on whether i is even or odd
	numU.SetInt64(int64(u))
	numV.SetInt64(int64(v))

	numModU.Exp(&numRadix, &numU, nil)
	numModV.Exp(&numRadix, &numV, nil)

	// Main Feistel Round, 8 times
	for i := 0; i < numRounds; i++ {
		// Determine Feistel Round parameters
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		// Calculate P by XORing W, i into the first 4 bytes of P
		// i only requires 1 byte, rest are 0 padding bytes
		// Anything XOR 0 is itself, so only need to XOR the last byte
		P[0] = W[0]
		P[1] = W[1]
		P[2] = W[2]
		P[3] = W[3] ^ byte(i)

		// The remaining 12 bytes of P are for rev(B) with padding
		_, ok = numB.SetString(rev(B), radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		numBBytes = numB.Bytes()

		// These middle bytes need to be reset to 0 for padding
		for x := 0; x < 12-len(numBBytes); x++ {
			P[halfTweakLen+x] = 0x00
		}

		copy(P[blockSize-len(numBBytes):], numBBytes)

		// Calculate S by operating on P in place
		revP := revB(P)

		// P is fixed-length 16 bytes, so this call cannot panic
		c.aesBlock.Encrypt(revP, revP)
		S = revB(revP)

		// Calculate numY
		numY.SetBytes(S[:])

		// Calculate c
		_, ok = numC.SetString(rev(A), radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		numC.Add(&numC, &numY)

		if i%2 == 0 {
			numC.Mod(&numC, &numModU)
		} else {
			numC.Mod(&numC, &numModV)
		}

		C := numC.Text(c.radix)

		// Need to pad the text with leading 0s first to make sure it's the correct length
		for len(C) < int(m) {
			C = "0" + C
		}
		C = rev(C)

		// Final steps
		A = B
		B = C
	}

	ret = A + B

	return ret, nil
}

// Decrypt decrypts the string X over the current FF3 parameters
// and returns the plaintext of the same length and format
func (c Cipher) Decrypt(X string) (string, error) {
	return c.DecryptWithTweak(X, c.tweak)
}

// DecryptWithTweak is the same as Decrypt except it uses the
// tweak from the parameter rather than the current Cipher's tweak
// This allows you to re-use a single Cipher (for a given key) and simply
// override the tweak for each unique data input, which is a practical
// use-case of FPE for things like credit card numbers.
func (c Cipher) DecryptWithTweak(X string, tweak []byte) (string, error) {
	var ret string
	var ok bool

	n := uint32(len(X))

	// Check if message length is within minLength and maxLength bounds
	// TODO BUG: when n==c.maxLen, it breaks. For now, I'm changing
	// the input check to >= instead of only >
	if (n < c.minLen) || (n >= c.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	// Make sure the given the length of tweak in bits is 64
	if len(tweak) != tweakLen {
		return ret, ErrTweakLengthInvalid
	}

	radix := c.radix

	// Check if the message is in the current radix
	var numX big.Int
	_, ok = numX.SetString(X, radix)
	if !ok {
		return ret, ErrStringNotInRadix
	}

	// Calculate split point
	u := uint32(math.Ceil(float64(n) / 2))
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Split the tweak
	Tl := tweak[:halfTweakLen]
	Tr := tweak[halfTweakLen:]

	// P is always 16 bytes
	var (
		P = make([]byte, blockSize)
		m uint32
		W []byte

		numA, numC       big.Int
		numRadix, numY   big.Int
		numU, numV       big.Int
		numModU, numModV big.Int
		S, numABytes     []byte
	)

	numRadix.SetInt64(int64(radix))

	// Pre-calculate the modulus since it's only one of 2 values,
	// depending on whether i is even or odd
	numU.SetInt64(int64(u))
	numV.SetInt64(int64(v))

	numModU.Exp(&numRadix, &numU, nil)
	numModV.Exp(&numRadix, &numV, nil)

	// Main Feistel Round, 8 times
	for i := numRounds - 1; i >= 0; i-- {
		// Determine Feistel Round parameters
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		// Calculate P by XORing W, i into the first 4 bytes of P
		// i only requires 1 byte, rest are 0 padding bytes
		// Anything XOR 0 is itself, so only need to XOR the last byte
		P[0] = W[0]
		P[1] = W[1]
		P[2] = W[2]
		P[3] = W[3] ^ byte(i)

		// The remaining 12 bytes of P are for rev(A) with padding
		_, ok = numA.SetString(rev(A), radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		numABytes = numA.Bytes()

		// These middle bytes need to be reset to 0 for padding
		for x := 0; x < 12-len(numABytes); x++ {
			P[halfTweakLen+x] = 0x00
		}

		copy(P[blockSize-len(numABytes):], numABytes)

		// Calculate S by operating on P in place
		revP := revB(P)

		// P is fixed-length 16 bytes, so this call cannot panic
		c.aesBlock.Encrypt(revP, revP)
		S = revB(revP)

		// Calculate numY
		numY.SetBytes(S[:])

		// Calculate numY
		numY.SetBytes(S[:])

		// Calculate c
		_, ok = numC.SetString(rev(B), radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		numC.Sub(&numC, &numY)

		if i%2 == 0 {
			numC.Mod(&numC, &numModU)
		} else {
			numC.Mod(&numC, &numModV)
		}

		C := numC.Text(c.radix)

		// Need to pad the text with leading 0s first to make sure it's the correct length
		for len(C) < int(m) {
			C = "0" + C
		}
		C = rev(C)

		// Final steps
		B = A
		A = C
	}

	return A + B, nil
}

// rev reverses a string
func rev(s string) string {
	return string(revB([]byte(s)))
}

// revB reverses a byte slice in place
func revB(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
