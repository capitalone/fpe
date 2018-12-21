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

// Package fpe provides some encoding helpers for use
// in the FF1 and FF3 format-preserving encryption packages.
package fpe

import (
	"fmt"
	"math/big"
)

// Num constructs a big.Int from an array of uint16, where each element represents
// one digit in the given radix.  The array is arranged with the most significant digit in element 0,
// down to the least significant digit in element len-1.
func Num(s []uint16, radix uint64) (big.Int, error) {
	var big_radix, bv, x big.Int
	if radix > 65536 {
		return x, fmt.Errorf("Radix (%d) too big: max supported radix is 65536", radix)
	}

	maxv := uint16(radix - 1)
	big_radix.SetUint64(uint64(radix))
	for i, v := range s {
		if v > maxv {
			return x, fmt.Errorf("Value at %d out of range: got %d - expected 0..%d", i, v, maxv)
		}
		bv.SetUint64(uint64(v))
		x.Mul(&x, &big_radix)
		x.Add(&x, &bv)
	}
	return x, nil
}

// Str populates an array of uint16 with digits representing big.Int x in the specified radix.
// The array is arranged with the most significant digint in element 0.
// The array is built from big.Int x from the least significant digit upwards.  If the supplied
// array is too short, the most significant digits of x are quietly lost.
func Str(x *big.Int, r []uint16, radix uint64) ([]uint16, error) {

	var big_radix, mod, v big.Int
	if radix > 65536 {
		return r, fmt.Errorf("Radix (%d) too big: max supported radix os 65536", radix)
	}
	m := len(r)
	v.Set(x)
	big_radix.SetUint64(radix)
	for i := range r {
		v.DivMod(&v, &big_radix, &mod)
		r[m-i-1] = uint16(mod.Uint64())
	}
	if v.Sign() != 0 {
		return r, fmt.Errorf("destination array too small: %s remains after conversion", &v)
	}
	return r, nil
}

// DecodeNum constructs a string from indices into the alphabet embedded in the Codec. The indices
// are encoded in the big Ints a and b.
// len_a and len_b are the number of characters that should be built from the corresponding big Ints.
func DecodeNum(a *big.Int, len_a int, b *big.Int, len_b int, c Codec) (string, error) {
	ret := make([]uint16, len_a+len_b)
	_, err := Str(a, ret[:len_a], uint64(c.Radix()))
	if err != nil {
		return "", err
	}
	_, err = Str(b, ret[len_a:], uint64(c.Radix()))
	if err != nil {
		return "", err
	}
	return c.Decode(ret)
}
