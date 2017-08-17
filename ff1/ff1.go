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
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
)

// Note that this is strictly following the official NIST spec guidelines. In the linked PDF Appendix A (README.md), NIST recommends that radix^minLength >= 1,000,000. If you would like to follow that, change this parameter.
const (
	feistelMin    = 100
	numRounds     = 10
	blockSize     = aes.BlockSize
	halfBlockSize = blockSize / 2
	// maxRadix   = 65536 // 2^16
)

var (
	// For all AES-CBC calls, IV is always 0
	ivZero = make([]byte, aes.BlockSize)

	// Errors
	ErrStringNotInRadix = errors.New("string is not within base/radix")
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

	// While FF1 allows radices in [2, 2^16],
	// realistically there's a practical limit based on the alphabet that can be passed in
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

	// aes.NewCipher automatically returns the correct block based on the length of the key passed in
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

	// Check if the message is in the current radix
	var bX big.Int
	_, ok := bX.SetString(X, radix)
	if !ok {
		return ret, ErrStringNotInRadix
	}

	// Calculate split point
	u := n / 2
	v := n - u

	// Split the message
	// TODO: A and B can actually be slices, just converted to strings the moment they need to
	A := X[:u]
	B := X[u:]

	// Byte lengths
	// TODO: can these calculations be done more efficiently?
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Calculate P, doesn't change in each loop iteration
	// P's length is always 16, so it can stay on the stack, separate from buf
	const lenP = blockSize
	P := make([]byte, aes.BlockSize)

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

	// Determinte lengths of byte slices

	// Q's length is known to always be t+b+1+numPad, to be multiple of 16
	lenQ := t + b + 1 + numPad

	// For a given input X, the size of PQ is deterministic: 16+lenQ
	lenPQ := lenP + lenQ

	// lenY := blockSize * maxJ

	// buf holds multiple components that change in each loop iteration
	// Ensure there's enough space for max(lenPQ, lenY)
	// Q, PQ, and Y (R, xored) will share underlying memory
	// The total buffer length needs space for:
	// Q (lenQ)
	// PQ (lenPQ)
	// Y = R(last block of PQ) + xored blocks (maxJ - 1)
	// TODO: Declare it as a fixed-size slice anyway so it starts on the stack, then use appends?
	totalBufLen := lenQ + lenPQ + (maxJ-1)*blockSize
	buf := make([]byte, totalBufLen)

	// TODO: small inputs will likely cause Q length to be 16,
	// could start with that with larger cap and expand as necessary?
	// Q will use the first lenQ bytes of buf
	// Only the last b+1 bytes of Q change for each loop iteration
	Q := buf[:lenQ]
	// This is the fixed part of Q
	// First t bytes of Q are the tweak, next numPad bytes are already zero-valued
	// TODO: Figure out why this is causing allocations
	copy(Q[:t], f.tweak)

	// Use PQ as a combined storage for P||Q
	// PQ will use the next 16+lenQ bytes of buf
	// Important: PQ is going to be encrypted in place,
	// so P and Q will also remain separate and copied in each iteration
	PQ := buf[lenQ : lenQ+lenPQ]

	// These are re-used in the for loop below
	var (
		// TODO: understand why c is causing many allocations
		numB, br, bm, mod, y, c big.Int
		numBBytes               []byte
		m                       int
	)

	br.SetInt64(int64(radix))

	// Y starts at the start of last block of PQ, requires lenY bytes
	// R is part of Y, Overlaps part of PQ
	Y := buf[lenQ+lenPQ-blockSize:]

	// R starts at Y, requires blockSize bytes,
	// which overlaps with the first block of PQ
	R := Y[:blockSize]

	// This will only be needed if maxJ > 1, for the inner for loop
	// xored uses the blocks after R in Y, if any
	xored := Y[blockSize:]

	// Main Feistel Round, 10 times
	for i := 0; i < numRounds; i++ {
		// Calculate the dynamic parts of Q
		Q[t+numPad] = byte(i)

		// TODO: In theory, this SetString doesn't have to be called each time
		// With each iteration, the radix never changes, which means when
		// A, B change at the end of the loop, they can just be swapped,
		// and they're already interepreted in the right radix
		_, ok = numB.SetString(B, radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}
		numBBytes = numB.Bytes()

		// These middle bytes need to be reset to 0
		for j := 0; j < (lenQ - t - numPad - len(numBBytes)); j++ {
			Q[t+numPad+j+1] = 0x00
		}

		// B must only take up the last b bytes
		copy(Q[lenQ-len(numBBytes):], numBBytes)

		// PQ = P||Q
		// Since prf/ciph will operate in place, P and Q have to be copied into PQ,
		// for each iteration to reset the contents
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// R is guaranteed to be of length 16
		R, err = f.prf(PQ)
		if err != nil {
			return ret, err
		}

		// Step 6iii
		for j := 1; j < maxJ; j++ {
			// offset is used to calculate which xored block to use in this iteration
			offset := (j - 1) * blockSize

			// Since xorBytes operates in place, xored needs to be cleared
			// Only need to clear the first 8 bytes since j will be put in for next 8
			for x := 0; x < halfBlockSize; x++ {
				xored[offset+x] = 0x00
			}
			binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+blockSize], uint64(j))

			// XOR R and j in place
			// R, xored are always 16 bytes
			for x := 0; x < aes.BlockSize; x++ {
				xored[offset+x] = R[x] ^ xored[offset+x]
			}

			// AES encrypt the current xored block
			_, err = f.ciph(xored[offset : offset+blockSize])
			if err != nil {
				return ret, err
			}
		}

		y.SetBytes(Y[:d])

		if i%2 == 0 {
			m = int(u)
		} else {
			m = int(v)
		}
		bm.SetInt64(int64(m))

		// Calculate c
		mod.Exp(&br, &bm, nil)

		_, ok = c.SetString(A, radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		c.Add(&c, &y)
		c.Mod(&c, &mod)

		// Interpret c as a string of the given radix of length m
		// Ensure any left padding to meet length m
		// TODO: pre-allocate C as a byte slice of length m
		C := c.Text(radix)
		for len(C) < m {
			C = "0" + C
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
	t := len(f.tweak)

	// Check if message length is within minLength and maxLength bounds
	if (n < f.minLen) || (n > f.maxLen) {
		return ret, errors.New("message length is not within min and max bounds")
	}

	radix := f.radix

	// Check if the message is in the current radix
	var bX big.Int
	_, ok := bX.SetString(X, radix)
	if !ok {
		return ret, ErrStringNotInRadix
	}

	// Calculate split point
	u := n / 2
	v := n - u

	// Split the message
	// TODO: A and B can actually be slices, just converted to strings the moment they need to
	A := X[:u]
	B := X[u:]

	// Byte lengths
	// TODO: can these calculations be done more efficiently?
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Calculate P, doesn't change in each loop iteration
	// P's length is always 16, so it can stay on the stack, separate from buf
	const lenP = blockSize
	P := make([]byte, aes.BlockSize)

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

	// Determinte lengths of byte slices

	// Q's length is known to always be t+b+1+numPad, to be multiple of 16
	lenQ := t + b + 1 + numPad

	// For a given input X, the size of PQ is deterministic: 16+lenQ
	lenPQ := lenP + lenQ

	// lenY := blockSize * maxJ

	// buf holds multiple components that change in each loop iteration
	// Ensure there's enough space for max(lenPQ, lenY)
	// Q, PQ, and Y (R, xored) will share underlying memory
	// The total buffer length needs space for:
	// Q (lenQ)
	// PQ (lenPQ)
	// Y = R(last block of PQ) + xored blocks (maxJ - 1)
	// TODO: Declare it as a fixed-size slice anyway so it starts on the stack, then use appends?
	totalBufLen := lenQ + lenPQ + (maxJ-1)*blockSize
	buf := make([]byte, totalBufLen)

	// TODO: small inputs will likely cause Q length to be 16,
	// could start with that with larger cap and expand as necessary?
	// Q will use the first lenQ bytes of buf
	// Only the last b+1 bytes of Q change for each loop iteration
	Q := buf[:lenQ]
	// This is the fixed part of Q
	// First t bytes of Q are the tweak, next numPad bytes are already zero-valued
	// TODO: Figure out why this is causing allocations
	copy(Q[:t], f.tweak)

	// Use PQ as a combined storage for P||Q
	// PQ will use the next 16+lenQ bytes of buf
	// Important: PQ is going to be encrypted in place,
	// so P and Q will also remain separate and copied in each iteration
	PQ := buf[lenQ : lenQ+lenPQ]

	// These are re-used in the for loop below
	var (
		// TODO: understand why c is causing many allocations
		numA, br, bm, mod, y, c big.Int
		numABytes               []byte
		m                       int
	)

	br.SetInt64(int64(radix))

	// Y starts at the start of last block of PQ, requires lenY bytes
	// R is part of Y, Overlaps part of PQ
	Y := buf[lenQ+lenPQ-blockSize:]

	// R starts at Y, requires blockSize bytes,
	// which overlaps with the first block of PQ
	R := Y[:blockSize]

	// This will only be needed if maxJ > 1, for the inner for loop
	// xored uses the blocks after R in Y, if any
	xored := Y[blockSize:]

	// Main Feistel Round, 10 times
	for i := numRounds - 1; i >= 0; i-- {
		// Calculate the dynamic parts of Q
		Q[t+numPad] = byte(i)

		// TODO: In theory, this SetString doesn't have to be called each time
		// With each iteration, the radix never changes, which means when
		// A, B change at the end of the loop, they can just be swapped,
		// and they're already interepreted in the right radix
		_, ok = numA.SetString(A, radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}
		numABytes = numA.Bytes()

		// These middle bytes need to be reset to 0
		for j := 0; j < (lenQ - t - numPad - len(numABytes)); j++ {
			Q[t+numPad+j+1] = 0x00
		}

		// B must only take up the last b bytes
		copy(Q[lenQ-len(numABytes):], numABytes)

		// PQ = P||Q
		// Since prf/ciph will operate in place, P and Q have to be copied into PQ,
		// for each iteration to reset the contents
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// R is guaranteed to be of length 16
		R, err = f.prf(PQ)
		if err != nil {
			return ret, err
		}

		// Step 6iii
		for j := 1; j < maxJ; j++ {
			// offset is used to calculate which xored block to use in this iteration
			offset := (j - 1) * blockSize

			// Since xorBytes operates in place, xored needs to be cleared
			// Only need to clear the first 8 bytes since j will be put in for next 8
			for x := 0; x < halfBlockSize; x++ {
				xored[offset+x] = 0x00
			}
			binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+blockSize], uint64(j))

			// XOR R and j in place
			// R, xored are always 16 bytes
			for x := 0; x < aes.BlockSize; x++ {
				xored[offset+x] = R[x] ^ xored[offset+x]
			}

			// AES encrypt the current xored block
			_, err = f.ciph(xored[offset : offset+blockSize])
			if err != nil {
				return ret, err
			}
		}

		y.SetBytes(Y[:d])

		if i%2 == 0 {
			m = int(u)
		} else {
			m = int(v)
		}
		bm.SetInt64(int64(m))

		// Calculate c
		mod.Exp(&br, &bm, nil)

		_, ok = c.SetString(B, radix)
		if !ok {
			return ret, ErrStringNotInRadix
		}

		c.Sub(&c, &y)
		c.Mod(&c, &mod)

		// Interpret c as a string of the given radix of length m
		// Ensure any left padding to meet length m
		// TODO: pre-allocate C as a byte slice of length m
		C := c.Text(radix)
		for len(C) < m {
			C = "0" + C
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
	return cipher[len(cipher)-aes.BlockSize:], nil
}
