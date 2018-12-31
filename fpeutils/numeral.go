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

// Package fpeutils provides some encoding helpers for use
// in the FF1 and FF3 format-preserving encryption packages.
package fpeutils

import (
	"fmt"
	"math/big"
)

// Num constructs a big.Int from an array of uint16, where each element represents
// one digit in the given radix.  The array is arranged with the most significant digit in element 0,
// down to the least significant digit in element len-1.
func Num(s []uint16, radix uint64) (big.Int, error) {
	var bigRadix, bv, x big.Int
	if radix > 65536 {
		return x, fmt.Errorf("Radix (%d) too big: max supported radix is 65536", radix)
	}

	maxv := uint16(radix - 1)
	bigRadix.SetUint64(uint64(radix))
	for i, v := range s {
		if v > maxv {
			return x, fmt.Errorf("Value at %d out of range: got %d - expected 0..%d", i, v, maxv)
		}
		bv.SetUint64(uint64(v))
		x.Mul(&x, &bigRadix)
		x.Add(&x, &bv)
	}
	return x, nil
}

// NumRev constructs a big.Int from an array of uint16, where each element represents
// one digit in the given radix.  The array is arranged with the least significant digit in element 0,
// down to the most significant digit in element len-1.
func NumRev(s []uint16, radix uint64) (big.Int, error) {
	var bigRadix, bv, x big.Int
	if radix > 65536 {
		return x, fmt.Errorf("Radix (%d) too big: max supported radix is 65536", radix)
	}

	maxv := uint16(radix - 1)
	bigRadix.SetUint64(uint64(radix))
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] > maxv {
			return x, fmt.Errorf("Value at %d out of range: got %d - expected 0..%d", i, s[i], maxv)
		}
		bv.SetUint64(uint64(s[i]))
		x.Mul(&x, &bigRadix)
		x.Add(&x, &bv)
	}
	return x, nil
}

// Str populates an array of uint16 with digits representing big.Int x in the specified radix.
// The array is arranged with the most significant digit in element 0.
// The array is built from big.Int x from the least significant digit upwards.  If the supplied
// array is too short, the most significant digits of x are quietly lost.
func Str(x *big.Int, r []uint16, radix uint64) ([]uint16, error) {

	var bigRadix, mod, v big.Int
	if radix > 65536 {
		return r, fmt.Errorf("Radix (%d) too big: max supported radix os 65536", radix)
	}
	m := len(r)
	v.Set(x)
	bigRadix.SetUint64(radix)
	for i := range r {
		v.DivMod(&v, &bigRadix, &mod)
		r[m-i-1] = uint16(mod.Uint64())
	}
	if v.Sign() != 0 {
		return r, fmt.Errorf("destination array too small: %s remains after conversion", &v)
	}
	return r, nil
}

// StrRev populates an array of uint16 with digits representing big.Int x in the specified radix.
// The array is arranged with the least significant digit in element 0.
// The array is built from big.Int x from the least significant digit upwards.  If the supplied
// array is too short, the most significant digits of x are quietly lost.
func StrRev(x *big.Int, r []uint16, radix uint64) ([]uint16, error) {

	var bigRadix, mod, v big.Int
	if radix > 65536 {
		return r, fmt.Errorf("Radix (%d) too big: max supported radix os 65536", radix)
	}
	v.Set(x)
	bigRadix.SetUint64(radix)
	for i := range r {
		v.DivMod(&v, &bigRadix, &mod)
		r[i] = uint16(mod.Uint64())
	}
	if v.Sign() != 0 {
		return r, fmt.Errorf("destination array too small: %s remains after conversion", &v)
	}
	return r, nil
}

// DecodeNum constructs a string from indices into the alphabet embedded in the Codec. The indices
// are encoded in the big Ints a and b.
// lenA and lenB are the number of characters that should be built from the corresponding big Ints.
func DecodeNum(a *big.Int, lenA int, b *big.Int, lenB int, c Codec) (string, error) {
	ret := make([]uint16, lenA+lenB)
	_, err := Str(a, ret[:lenA], uint64(c.Radix()))
	if err != nil {
		return "", err
	}
	_, err = Str(b, ret[lenA:], uint64(c.Radix()))
	if err != nil {
		return "", err
	}
	return c.Decode(ret)
}
