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
	"unicode/utf8"
)

// Codec supports the conversion of an arbitrary alphabet into ordinal
// values from 0 to length of alphabet-1.
// Element 'rtu' (rune-to-uint16) supports the mapping from runes to ordinal values.
// Element 'utr' (uint16-to-rune) supports the mapping from ordinal values to runes.
type Codec struct {
	rtu map[rune]uint16
	utr []rune
}

// NewCodec builds a Codec from the set of unique characters taken from the string s.
// The string contains arbitrary Utf-8 characters.
// It is an error to try to construct a codec from an alphabet with more the 65536 characters.
func NewCodec(s string) (Codec, error) {
	var ret Codec
	ret.rtu = make(map[rune]uint16)
	ret.utr = make([]rune, utf8.RuneCountInString(s))

	var i uint32
	for _, rv := range s {
		// duplicates are tolerated, but ignored.
		if _, ok := ret.rtu[rv]; !ok {
			ret.utr[i] = rv
			ret.rtu[rv] = uint16(i)
			if i == 65536 {
				return ret, fmt.Errorf("alphabet must contain no more than 65536 characters")
			}
			i++
		}
	}
	// shrink utr to unique characters
	ret.utr = ret.utr[0:i]
	return ret, nil
}

// Radix returns the size of the alphabet supported by the Codec.
func (a *Codec) Radix() int {
	return len(a.utr)
}

// Encode the supplied string as an array of ordinal values giving the
// position of each character in the alphabet.
// It is an error for the supplied string to contain characters than are not
// in the alphabet.
func (a *Codec) Encode(s string) ([]uint16, error) {
	n := utf8.RuneCountInString(s)
	c := n
	if n%2 == 1 {
		// ensure the numeral array has even-sized capacity for FF3
		c++
	}
	ret := make([]uint16, n, c)

	var ok bool
	i := 0
	for _, rv := range s {
		ret[i], ok = a.rtu[rv]
		if !ok {
			return ret, fmt.Errorf("character at position %d is not in alphabet", i)
		}
		i++
	}
	return ret, nil
}

// Decode constructs a string from an array of ordinal values where each
// value specifies the position of the character in the alphabet.
// It is an error for the array to contain values outside the boundary of the
// alphabet.
func (a *Codec) Decode(n []uint16) (string, error) {
	var ret string
	for i, v := range n {
		if v < 0 || int(v) > len(a.utr)-1 {
			return ret, fmt.Errorf("numeral at position %d out of range: %d not in [0..%d]", i, v, len(a.utr)-1)
		}
		ret = ret + string(a.utr[v])
	}
	return ret, nil
}
