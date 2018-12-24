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

package ff3

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF3samples.pdf

type testVector struct {
	radix      int
	key        string
	tweak      string
	plaintext  string
	ciphertext string
}

var testVectors = []testVector{
	// AES-128
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A94",
		"D8E7920AFA330A73",
		"890121234567890000",
		"750918814058654607",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A94",
		"9A768A92F60E12D8",
		"890121234567890000",
		"018989839189395384",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A94",
		"D8E7920AFA330A73",
		"89012123456789000000789000000",
		"48598367162252569629397416226",
	},
	{
		10, "EF4359D8D580AA4F7F036D6F04FC6A94",
		"0000000000000000",
		"89012123456789000000789000000",
		"34695224821734535122613701434",
	},
	{
		26, "EF4359D8D580AA4F7F036D6F04FC6A94",
		"9A768A92F60E12D8",
		"0123456789abcdefghi",
		"g2pk40i992fn20cjakb",
	},

	// AES-192
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"D8E7920AFA330A73",
		"890121234567890000",
		"646965393875028755",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"9A768A92F60E12D8",
		"890121234567890000",
		"961610514491424446",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"D8E7920AFA330A73",
		"89012123456789000000789000000",
		"53048884065350204541786380807",
	},
	{
		10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"0000000000000000",
		"89012123456789000000789000000",
		"98083802678820389295041483512",
	},
	{
		26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"9A768A92F60E12D8",
		"0123456789abcdefghi",
		"i0ihe2jfj7a9opf9p88",
	},

	// AES-256
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"D8E7920AFA330A73",
		"890121234567890000",
		"922011205562777495",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"9A768A92F60E12D8",
		"890121234567890000",
		"504149865578056140",
	},
	{
		10,
		"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"D8E7920AFA330A73",
		"89012123456789000000789000000",
		"04344343235792599165734622699",
	},
	{
		10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"0000000000000000",
		"89012123456789000000789000000",
		"30859239999374053872365555822",
	},
	{
		26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"9A768A92F60E12D8",
		"0123456789abcdefghi",
		"p0b2godfja9bhb7bk38",
	},
}

func TestEncrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(testVector.radix, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			ciphertext, err := ff3.Encrypt(testVector.plaintext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if ciphertext != testVector.ciphertext {
				t.Fatalf("\nSample%d\nRadix:\t\t%d\nKey:\t\t%s\nTweak:\t\t%s\nPlaintext:\t%s\nCiphertext:\t%s\nExpected:\t%s", sampleNumber, testVector.radix, testVector.key, testVector.tweak, testVector.plaintext, ciphertext, testVector.ciphertext)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(testVector.radix, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			plaintext, err := ff3.Decrypt(testVector.ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if plaintext != testVector.plaintext {
				t.Fatalf("\nSample%d\nRadix:\t\t%d\nKey:\t\t%s\nTweak:\t\t%s\nCiphertext:\t%s\nPlaintext:\t%s\nExpected:\t%s", sampleNumber, testVector.radix, testVector.key, testVector.tweak, testVector.ciphertext, plaintext, testVector.plaintext)
			}
		})
	}
}

func TestAlphabetSizes(t *testing.T) {
	// encryption deals with numeral values encoded in ceil(log(radix))-sized
	// bit strings, up to 16 bits in length - the number of bits in a uint16.
	// This test exercises behaviour for all bitstring lengths from 1 to 16.

	key, _ := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, _ := hex.DecodeString("D8E7920AFA330A73")

	for s := uint(1); s < 17; s++ {
		a, err := buildAlphabet(1 << s)
		if err != nil {
			t.Fatalf("TestAlphabetSizes: %s", err)
		}

		ff3, err := NewAlphaCipher(a, key, tweak)
		if err != nil {
			t.Fatalf("Unable to create cipher: %v", err)
		}

		plaintext := strings.Repeat(string(rune(0)), 10)
		ciphertext, err := ff3.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("%v", err)
		}

		decrypted, err := ff3.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("%v", err)
		}

		if plaintext != decrypted {
			t.Fatalf("TestUnicode Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
		}

	}

}

func buildAlphabet(n int) (string, error) {
	// Not every code-point can be encoded as utf-8 string.
	// For example u+DC00 - u+DFFF contains "isolated surrogate code points"
	// that have no string interpretation.
	// (https://www.unicode.org/charts/PDF/UDC00.pdf)
	//
	// Loop through a large number of code points and collect
	// up to n code points with valid interpretations.
	var alphabet bytes.Buffer
	nr := 0
	for i := 0; i < 100000; i++ {
		if utf8.ValidRune(rune(i)) {
			s := string(rune(i))
			nr++
			alphabet.WriteString(s)
			if nr == n {
				return alphabet.String(), nil
			}
		}
	}
	return alphabet.String(), fmt.Errorf("Failed to collect %d validrunes: only %d collected", n, nr)
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Encrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// Create a new FF3 cipher "object"
	// 10 is the radix/base
	FF3, err := NewCipher(10, key, tweak)
	if err != nil {
		panic(err)
	}

	original := "890121234567890000"

	// Call the encryption function on an example test vector
	ciphertext, err := FF3.Encrypt(original)
	if err != nil {
		panic(err)
	}

	fmt.Println(ciphertext)
	// Output: 750918814058654607
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Decrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// Create a new FF3 cipher "object"
	// 10 is the radix/base
	FF3, err := NewCipher(10, key, tweak)
	if err != nil {
		panic(err)
	}

	ciphertext := "750918814058654607"

	plaintext, err := FF3.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	// Output: 890121234567890000
}

func BenchmarkEncrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(testVector.radix, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff3.Encrypt(testVector.plaintext)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(testVector.radix, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff3.Decrypt(testVector.ciphertext)
			}
		})
	}
}
