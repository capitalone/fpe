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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
	"strings"
)

// Note that this is strictly following the official NIST guidelines. In the linked PDF Appendix A (READHME.md), NIST recommends that radix^minLength >= 1,000,000. If you would like to follow that, change this parameter.
const (
	feistelMin = 100
	numRounds  = 8
)

// For all AES-CBC calls, IV is always 0
var ivZero [aes.BlockSize]byte

// Need this for the SetIV function which CBCEncryptor has, but cipher.BlockMode interface doesn't.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// A Cipher is an instance of the FF3 mode of format preserving encryption
// using a particular key, radix, and tweak
type Cipher struct {
	tweak  []byte
	radix  int
	minLen uint32
	maxLen uint32

	// Re-usable CBC encryptor with exported SetIV function
	cbcEncryptor cipher.BlockMode
}

// NewCipher initializes a new FF3 Cipher for encryption or decryption use
// based on the radix, key and tweak parameters.
func NewCipher(radix int, key []byte, tweak []byte) (*Cipher, error) {
	keyLen := len(key)

	// Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
	if (keyLen != 16) && (keyLen != 24) && (keyLen != 32) {
		return nil, errors.New("key length must be 128, 192, or 256 bits")
	}

	// While FF3 allows radices in [2, 2^16], there is a practical limit to 36 (alphanumeric) because the Go math/big library only supports up to base 36.
	if (radix < 2) || (radix > big.MaxBase) {
		return nil, errors.New("radix must be between 2 and 36, inclusive")
	}

	// Make sure the given the length of tweak in bits is 64
	if len(tweak) != 8 {
		return nil, errors.New("tweak must be 8 bytes, or 64 bits")
	}

	// Calculate minLength - according to the spec, radix^minLength >= 100.
	minLen := uint32(math.Ceil(math.Log(feistelMin) / math.Log(float64(radix))))

	maxLen := uint32(math.Floor((192 / math.Log2(float64(radix)))))

	// Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
	if (minLen < 2) || (maxLen < minLen) || (float64(maxLen) > (192 / math.Log2(float64(radix)))) {
		return nil, errors.New("minLen or maxLen invalid, adjust your radix")
	}

	// aes.NewCipher automatically returns the correct block based on the length of the key passed in.
	aesBlock, err := aes.NewCipher(revB(key))
	if err != nil {
		panic(err)
	}

	cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero[:])

	return &Cipher{
		tweak:        tweak,
		radix:        radix,
		minLen:       minLen,
		maxLen:       maxLen,
		cbcEncryptor: cbcEncryptor,
	}, nil
}

// Encrypt encrypts the string X over the current FF3 parameters
// and returns the ciphertext of the same length and format
func (f Cipher) Encrypt(X string) (string, error) {
	var ret string
	var err error

	n := uint32(len(X))

	// Check if message length is within minLength and maxLength bounds
	// BUG: when n==f.maxLen, it breaks. For now, I'm changing
	// the input check to >= instead of only >
	if (n < f.minLen) || (n >= f.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	// Check if the message is in the current radix by using the numRadix function
	_, err = numRadix(X, f.radix)
	if err != nil {
		return ret, errors.New("message is not within base/radix")
	}

	// Calculate split point
	u := uint32(math.Ceil(float64(n) / 2))
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Split the tweak
	Tl := f.tweak[:4]
	Tr := f.tweak[4:]

	// Main Feistel Round, 8 times
	for i := 0; i < numRounds; i++ {
		var m uint32
		var W []byte

		// Determine Feistel Round parameters
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		// Calculate P
		var xored []byte
		xored, err = xorBytes(W, []byte{0x00, 0x00, 0x00, byte(i)})
		if err != nil {
			return ret, err
		}
		P := bytes.NewBuffer(xored)

		var numB *big.Int
		numB, err = numRadix(rev(B), f.radix)
		if err != nil {
			return ret, err
		}

		numBBytes := numB.Bytes()

		_, err = P.Write(append(make([]byte, 12-len(numBBytes)), numBBytes...))
		if err != nil {
			return ret, err
		}

		// Calculate S
		var S []byte
		S, err = f.ciph(revB(P.Bytes()))
		if err != nil {
			return ret, err
		}

		copy(S[:], revB(S[:]))

		// Calculate y
		y := big.NewInt(0)
		y.SetBytes(S[:])

		// Calculate c
		mod := big.NewInt(0)
		mod.Exp(big.NewInt(int64(f.radix)), big.NewInt(int64(m)), nil)

		var c *big.Int
		c, err = numRadix(rev(A), f.radix)
		if err != nil {
			return ret, err
		}

		c.Add(c, y)
		c.Mod(c, mod)

		C := c.Text(f.radix)
		if (len(C)) < int(m) {
			C = strings.Repeat("0", int(m)-len(C)) + C
		}
		C = rev(C)

		// Final steps
		A = B
		B = C
	}

	ret = A + B

	return ret, nil
}

var zeros = make([]byte, 16)

// Decrypt decrypts the string X over the current FF3 parameters
// and returns the plaintext of the same length and format
func (f Cipher) Decrypt(X string) (string, error) {
	var ret string
	var err error

	n := uint32(len(X))

	// Check if message length is within minLength and maxLength bounds
	if (n < f.minLen) || (n >= f.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	// Check if the message is in the current radix by using the numRadix function
	_, err = numRadix(X, f.radix)
	if err != nil {
		return ret, errors.New("message is not within base/radix")
	}

	// Calculate split point
	u := uint32(math.Ceil(float64(n) / 2))
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Split the tweak
	Tl := f.tweak[:4]
	Tr := f.tweak[4:]

	// cache for c
	var (
		P            bytes.Buffer
		bmod, numA   big.Int
		br, bm, y, c big.Int
	)

	// Main Feistel Round, 8 times
	for i := numRounds - 1; i >= 0; i-- {
		P.Reset()
		var m uint32
		var W []byte

		// Determine Feistel Round parameters
		if i%2 == 0 {
			m = u
			W = Tr
		} else {
			m = v
			W = Tl
		}

		// Calculate P
		var xored []byte
		xored, err = xorBytes(W, []byte{0x00, 0x00, 0x00, byte(i)})
		if err != nil {
			return ret, err
		}
		P.Write(xored)

		_, ok := numA.SetString(rev(A), f.radix)
		if !ok {
			return ret, errors.New("numRadix failed")
		}

		numABytes := numA.Bytes()
		P.Write(zeros[0 : 12-len(numABytes)])
		P.Write(numABytes)

		// Calculate S
		S, err := f.ciph(revB(P.Bytes()))
		if err != nil {
			return ret, err
		}
		copy(S[:], revB(S[:]))

		// Calculate y
		y.SetBytes(S[:])

		// Calculate c
		br.SetInt64(int64(f.radix))
		bm.SetInt64(int64(m))
		bmod.Exp(&br, &bm, nil)

		_, ok = c.SetString(rev(B), f.radix)
		if !ok {
			return ret, errors.New("numRadix failed")
		}
		c.Sub(&c, &y)
		c.Mod(&c, &bmod)

		// Need to pad the text with leading 0s first to make sure it's the correct length
		C := c.Text(f.radix)
		if (len(C)) < int(m) {
			C = strings.Repeat("0", int(m)-len(C)) + C
		}
		C = rev(C)

		// Final steps
		B = A
		A = C
	}

	return A + B, nil
}

// ciph defines how the main block cipher is called.
// When called otherwise, it is guaranteed to be a single-block (16-byte) input because that's what the algorithm dictates. In this situation, ciph behaves as ECB mode
func (f *Cipher) ciph(input []byte) ([]byte, error) {
	if len(input)%aes.BlockSize != 0 {
		return nil, errors.New("Length of ciph input must be multiple of 16")
	}
	f.cbcEncryptor.CryptBlocks(input, input)

	// Reset IV to 0
	f.cbcEncryptor.(cbcMode).SetIV(ivZero[:])
	return input, nil
}

// numRadix interprets a string of digits as a number. Same as ParseUint but using math/big library
func numRadix(str string, base int) (*big.Int, error) {
	out, success := big.NewInt(0).SetString(str, base)

	if !success || out == nil {
		return nil, errors.New("numRadix failed")
	}

	return out, nil
}

// XORs two byte arrays
// Assumes a and b are of same length
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("inputs to xorBytes must be of same length")
	}
	for i := 0; i < len(a); i++ {
		b[i] = a[i] ^ b[i]
	}
	return b, nil
}

// Returns the reversed version of an arbitrary string
func rev(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Returns the reversed version of a byte array
func revB(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
