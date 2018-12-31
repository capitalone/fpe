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
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"unicode/utf8"
)

var testCodec = []struct {
	alphabet string
	radix    int
	input    string
	output   []uint16
	error    bool
}{
	{
		"0123456789abcdefghijklmnopqrstuvwxyz ",
		37,
		"hello world",
		[]uint16{17, 14, 21, 21, 24, 36, 32, 24, 27, 21, 13},
		false,
	},
	{
		"hello world",
		8,
		"hello world",
		[]uint16{0, 1, 2, 2, 3, 4, 5, 3, 6, 2, 7},
		false,
	},
	{
		"hello world\u2318-",
		10,
		"\u2318 - hello world",
		[]uint16{8, 4, 9, 4, 0, 1, 2, 2, 3, 4, 5, 3, 6, 2, 7},
		false,
	},
}

func TestCodec(t *testing.T) {
	for idx, spec := range testCodec {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			al, err := NewCodec(spec.alphabet)
			if err != nil {
				t.Fatalf("Error making codec: %s", err)
			}
			if al.Radix() != spec.radix {
				t.Fatalf("Incorrect radix %d - expected %d", al.Radix(), spec.radix)
			}

			es, err := al.Encode(spec.input)
			if err != nil {
				t.Fatalf("Unable to encode '%s' using alphabet '%s': %s", spec.input, spec.alphabet, err)
			}

			if !reflect.DeepEqual(spec.output, es) {
				t.Fatalf("Encode output incorrect: %v", es)
			}

			s, err := al.Decode(es)
			if err != nil {
				t.Fatalf("Unable to decode: %s", err)
			}

			if s != spec.input {
				t.Fatalf("Decode error: got '%s' expected '%s'", s, spec.input)
			}
		})
	}
}

func TestEncoder(t *testing.T) {
	tests := []struct {
		alphabet string
		radix    int
		input    string
	}{
		{
			"",
			0,
			"hello world",
		},
		{
			"helloworld",
			7,
			"hello world",
		},
	}

	for idx, spec := range tests {
		t.Run(fmt.Sprintf("Sample%d", idx+1), func(t *testing.T) {
			al, err := NewCodec(spec.alphabet)
			if err != nil {
				t.Fatalf("Error making codec: %s", err)
			}
			if al.Radix() != spec.radix {
				t.Fatalf("Incorrect radix %d - expected %d", al.Radix(), spec.radix)
			}

			_, err = al.Encode(spec.input)
			if err == nil {
				t.Fatalf("Encode unexpectedly succeeded: input '%s', alphabet '%s'", spec.input, spec.alphabet)
			}
		})
	}
}

func TestLargeAlphabet(t *testing.T) {
	var alphabet bytes.Buffer

	nr := 0
	for i := 0; i < 100000; i++ {
		if utf8.ValidRune(rune(i)) {
			s := string(rune(i))
			nr++
			alphabet.WriteString(s)
			if nr == 65536 {
				break
			}
		}
	}

	al, err := NewCodec(alphabet.String())
	if err != nil {
		t.Fatalf("Error making codec: %s", err)
	}
	if al.Radix() != 65536 {
		t.Fatalf("Incorrect radix %d ", al.Radix())
	}

	nml, err := al.Encode("hello world")
	if err != nil {
		t.Fatalf("Unable to encode: %s", err)
	}

	_, err = al.Decode(nml)
	if err != nil {
		t.Fatalf("Unable to decode: %s", err)
	}
}
