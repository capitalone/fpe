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

// Package ff1 implements the FF1 format-preserving encryption
// algorithm/scheme
package ff1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"strings"
)

// Note that this is strictly following the official NIST spec guidelines. In the linked PDF Appendix A (README.md), NIST recommends that radix^minLength >= 1,000,000. If you would like to follow that, change this parameter.
const (
	feistelMin = 100
	numRounds  = 10
	// maxRadix   = 65536 // 2^16
)

var (
	// For all AES-CBC calls, IV is always 0
	ivZero = make([]byte, aes.BlockSize)

	// Errors
	ErrNumRadixFailed = errors.New("numRadix failed")
)

// Need this for the SetIV function which CBCEncryptor has, but cipher.BlockMode interface doesn't.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// A Cipher is an instance of the FF1 mode of format preserving encryption
// using a particular key, radix, and tweak
type Cipher struct {
	tweak  []byte
	radix  int
	minLen uint32
	maxLen uint32

	// Re-usable CBC encryptor with exported SetIV function
	cbcEncryptor cipher.BlockMode
}

// NewCipher initializes a new FF1 Cipher for encryption or decryption use
// based on the radix, max tweak length, key and tweak parameters.
func NewCipher(radix int, maxTLen int, key []byte, tweak []byte) (*Cipher, error) {
	keyLen := len(key)

	// Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
	if (keyLen != 16) && (keyLen != 24) && (keyLen != 32) {
		return nil, errors.New("key length must be 128, 192, or 256 bits")
	}

	// While FF1 allows radices in [2, 2^16], realistically there's a practical limit based on the alphabet that can be passed in
	if (radix < 2) || (radix > big.MaxBase) {
		return nil, errors.New("radix must be between 2 and 36, inclusive")
	}

	// Make sure the given the length of tweak is in range
	if (len(tweak) < 0) || (len(tweak) > maxTLen) {
		return nil, errors.New("tweak must be between 0 and maxTLen, inclusive")
	}

	// Calculate minLength
	minLen := uint32(math.Ceil(math.Log(feistelMin) / math.Log(float64(radix))))

	var maxLen uint32 = math.MaxUint32

	// Make sure 2 <= minLength <= maxLength < 2^32 is satisfied
	if (minLen < 2) || (maxLen < minLen) || (maxLen > math.MaxUint32) {
		return nil, errors.New("minLen invalid, adjust your radix")
	}

	// aes.NewCipher automatically returns the correct block based on the length of the key passed in.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES block")
	}

	cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero)

	return &Cipher{
		tweak:        tweak,
		radix:        radix,
		minLen:       minLen,
		maxLen:       maxLen,
		cbcEncryptor: cbcEncryptor,
	}, nil
}

// Encrypt encrypts the string X over the current FF1 parameters
// and returns the ciphertext of the same length and format
func (f *Cipher) Encrypt(X string) (string, error) {
	var ret string
	var err error

	n := uint32(len(X))
	t := len(f.tweak)

	// Check if message length is within minLength and maxLength bounds
	if (n < f.minLen) || (n > f.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	radix := f.radix

	// Check if the message is in the current radix by using the same logic as numRadix
	var bX big.Int
	_, ok := bX.SetString(X, radix)
	if !ok {
		return ret, errors.New("message is not within base/radix")
	}

	// Calculate split point
	u := n / 2
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Byte lengths
	// TODO: can these calculations be done more efficiently?
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	// P's length is always 16
	const lenP = 16
	P := make([]byte, lenP)

	// This is the fixed part of Q
	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Q's length is known to be t+b+1+numPad, to be multiple of 16
	// TODO: small inputs will likely cause Q length to be 16,
	// could start with that with larger cap and expand as necessary?
	lenQ := t + b + 1 + numPad
	Q := make([]byte, lenQ)

	// Use PQ as a combined storage for P||Q.
	// Only the last b+1 bytes of Q change for each loop iteration
	// For a given input X, the size of PQ is deterministic
	// PQ's length will always be len(P) + len(Q) = 16 + len(Q)
	// Important: PQ is going to be encrypted in place,
	// so P and Q will also remain separate and copied in
	PQ := make([]byte, lenP+lenQ)

	// Calculate P, which is always the first 16 bytes of PQ
	P[0] = 0x01
	P[1] = 0x02
	P[2] = 0x01

	// radix must fill 3 bytes, so pad 1 zero byte
	P[3] = 0x00
	binary.BigEndian.PutUint16(P[4:6], uint16(radix))

	P[6] = 0x0a
	P[7] = byte(u) // overflow automatically does the modulus

	binary.BigEndian.PutUint32(P[8:12], n)
	binary.BigEndian.PutUint32(P[12:lenP], uint32(t))

	// These are re-used in the for loop below
	var (
		// R is gauranteed to be 16 bytes since it holds output of PRF
		R = make([]byte, 16)

		// TODO: understand why c is causing many allocations
		numB, br, bm, mod, y, c big.Int

		// TODO: rename temp
		temp, numBBytes, Y []byte
	)

	br.SetInt64(int64(radix))

	// First t bytes of Q are the tweak, next numPad bytes are already zero-valued
	copy(Q[:t], f.tweak)

	// temp must be 16 bytes incuding j
	// This will only be needed if maxJ > 1, for the inner for loop
	maxJ := int(math.Ceil(float64(d) / 16))
	if maxJ > 1 {
		temp = make([]byte, 16)
	}

	// Main Feistel Round, 10 times
	for i := 0; i < numRounds; i++ {
		// Calculate the dynamic parts of Q
		Q[t+numPad] = byte(i)

		_, ok = numB.SetString(B, radix)
		if !ok {
			return ret, ErrNumRadixFailed
		}
		numBBytes = numB.Bytes()

		// These middle bytes need to be reset to 0
		for j := 0; j < (lenQ - t - numPad - len(numBBytes)); j++ {
			Q[t+numPad+j+1] = 0x00
		}

		// B must only take up the last b bytes
		copy(Q[lenQ-len(numBBytes):], numBBytes)

		// PQ = P||Q
		copy(PQ[:lenP], P)
		copy(PQ[lenP:], Q)

		R, err = f.prf(PQ)
		if err != nil {
			return ret, err
		}

		Y = R
		for j := 1; j < maxJ; j++ {
			binary.BigEndian.PutUint64(temp[8:], uint64(j))

			var xored []byte
			xored, err = xorBytes(R, temp)
			if err != nil {
				return ret, err
			}

			var cipher []byte
			cipher, err = f.ciph(xored)
			if err != nil {
				return ret, err
			}

			Y = append(Y, cipher...)
		}

		var m int
		if i%2 == 0 {
			m = int(u)
		} else {
			m = int(v)
		}
		bm.SetInt64(int64(m))

		y.SetBytes(Y[:d])

		// Calculate c
		mod.Exp(&br, &bm, nil)

		_, ok = c.SetString(A, radix)
		if !ok {
			return ret, ErrNumRadixFailed
		}

		c.Add(&c, &y)
		c.Mod(&c, &mod)

		C := c.Text(radix)
		if (len(C)) < m {
			C = strings.Repeat("0", m-len(C)) + C
		}

		A = B
		B = C
	}

	ret = A + B

	return ret, nil
}

// Decrypt decrypts the string X over the current FF1 parameters
// and returns the plaintext of the same length and format
func (f *Cipher) Decrypt(X string) (string, error) {
	var ret string
	var err error

	n := uint32(len(X))
	t := uint32(len(f.tweak))

	// Check if message length is within minLen and maxLen bounds
	if (n < f.minLen) || (n > f.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	// Check if the message is in the current radix by using the numRadix function
	_, err = numRadix(X, f.radix)
	if err != nil {
		return ret, errors.New("message is not within base/radix")
	}

	// Calculate split point
	u := uint32(math.Floor(float64(n) / 2))
	v := n - u

	// Split the message
	A := X[:u]
	B := X[u:]

	// Byte lengths
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(f.radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	// Calculate P
	P := bytes.NewBuffer([]byte{})
	_, err = P.Write([]byte{0x01, 0x02, 0x01, 0x00})
	if err != nil {
		return ret, err
	}

	err = binary.Write(P, binary.BigEndian, uint16(f.radix))
	if err != nil {
		return ret, err
	}

	err = P.WriteByte(0x0a)
	if err != nil {
		return ret, err
	}

	err = P.WriteByte(uint8(u % 256))
	if err != nil {
		return ret, err
	}

	err = binary.Write(P, binary.BigEndian, n)
	if err != nil {
		return ret, err
	}

	err = binary.Write(P, binary.BigEndian, t)
	if err != nil {
		return ret, err
	}

	// Main Feistel Round, 10 times
	for i := numRounds - 1; i >= 0; i-- {
		// Calculate Q
		Q := bytes.NewBuffer(f.tweak)

		numPad := (-int(t) - b - 1) % 16
		if numPad < 0 {
			numPad += 16
		}

		_, err = Q.Write(make([]byte, numPad))
		if err != nil {
			return ret, err
		}
		err = Q.WriteByte(byte(i))
		if err != nil {
			return ret, err
		}

		// A must only take up b bytes
		var numA *big.Int
		numA, err = numRadix(A, f.radix)
		if err != nil {
			return ret, err
		}

		numABytes := numA.Bytes()

		_, err = Q.Write(append(make([]byte, b-len(numABytes)), numABytes...))
		if err != nil {
			return ret, err
		}

		R, err := f.prf(append(P.Bytes(), Q.Bytes()...))
		if err != nil {
			return ret, err
		}

		Y := bytes.NewBuffer(R)
		maxJ := int(math.Ceil(float64(d) / 16))
		for j := 1; j < maxJ; j++ {
			// temp must be 16 bytes
			temp := bytes.NewBuffer(make([]byte, 8))
			err = binary.Write(temp, binary.BigEndian, uint64(j))
			if err != nil {
				return ret, err
			}

			var xored []byte
			xored, err = xorBytes(R, temp.Bytes())
			if err != nil {
				return ret, err
			}

			var cipher []byte
			cipher, err = f.ciph(xored)
			if err != nil {
				return ret, err
			}

			_, err = Y.Write(cipher)
			if err != nil {
				return ret, err
			}
		}

		S := Y.Bytes()[:d]

		var m int
		if i%2 == 0 {
			m = int(u)
		} else {
			m = int(v)
		}

		y := big.NewInt(0)
		y.SetBytes(S[:])

		// Calculate c
		mod := big.NewInt(0)
		mod.Exp(big.NewInt(int64(f.radix)), big.NewInt(int64(m)), nil)

		c, err := numRadix(B, f.radix)
		if err != nil {
			return ret, err
		}

		c.Sub(c, y)
		c.Mod(c, mod)

		C := c.Text(f.radix)
		if (len(C)) < m {
			C = strings.Repeat("0", m-len(C)) + C
		}

		B = A
		A = C
	}

	ret = A + B

	return ret, nil
}

// ciph defines how the main block cipher is called.
// When prf calls this, it will likely be a multi-block input, in which case ciph behaves as CBC mode with IV=0.
// When called otherwise, it is guaranteed to be a single-block (16-byte) input because that's what the algorithm dictates. In this situation, ciph behaves as ECB mode
func (f *Cipher) ciph(input []byte) ([]byte, error) {
	// These are checked here manually because the CryptBlocks function panics rather than returning an error
	// So, catch the potential error earlier
	if len(input)%aes.BlockSize != 0 {
		return nil, errors.New("length of ciph input must be multiple of 16")
	}

	f.cbcEncryptor.CryptBlocks(input, input)

	// Reset IV to 0
	f.cbcEncryptor.(cbcMode).SetIV(ivZero)

	return input, nil
}

// PRF as defined in the NIST spec is actually just AES-CBC-MAC, which is the last block of an AES-CBC encrypted ciphertext. Utilize the ciph function for the AES-CBC.
// PRF always outputs 16 bytes (one block)
func (f *Cipher) prf(input []byte) ([]byte, error) {
	cipher, err := f.ciph(input)
	if err != nil {
		return nil, err
	}

	// Only return the last block (CBC-MAC)
	out := cipher[len(cipher)-aes.BlockSize:]
	return out, nil
}

// numRadix interprets a string of digits as a number. Same as ParseUint but using math/big library
func numRadix(str string, base int) (*big.Int, error) {
	out, success := big.NewInt(0).SetString(str, base)

	if !success || out == nil {
		return nil, ErrNumRadixFailed
	}

	return out, nil
}

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
