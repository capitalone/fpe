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

package ff1

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf

// As Golang's sub-tests were introduced in Go 1.7, but this package will work with Go 1.6+, so I'm keeping sub-tests in a separate branch for now.

type testVector struct {
	radix int

	// Key and tweak are both hex-encoded strings
	key        string
	tweak      string
	plaintext  string
	ciphertext string
}

// Official NIST FF1 Test Vectors
var testVectors = []testVector{
	// AES-128
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"",
		"0123456789",
		"2433477484",
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"39383736353433323130",
		"0123456789",
		"6124200773",
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"3737373770717273373737",
		"0123456789abcdefghi",
		"a9tv40mll9kdu509eum",
	},

	// AES-192
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"",
		"0123456789",
		"2830668132",
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"39383736353433323130",
		"0123456789",
		"2496655549",
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"3737373770717273373737",
		"0123456789abcdefghi",
		"xbj3kv35jrawxv32ysr",
	},

	// AES-256
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"",
		"0123456789",
		"6657667009",
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"39383736353433323130",
		"0123456789",
		"1001623463",
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"3737373770717273373737",
		"0123456789abcdefghi",
		"xs8a0azh2avyalyzuwd",
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

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			ciphertext, err := ff1.Encrypt(testVector.plaintext)
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

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			plaintext, err := ff1.Decrypt(testVector.ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if plaintext != testVector.plaintext {
				t.Fatalf("\nSample%d\nRadix:\t\t%d\nKey:\t\t%s\nTweak:\t\t%s\nCiphertext:\t%s\nPlaintext:\t%s\nExpected:\t%s", sampleNumber, testVector.radix, testVector.key, testVector.tweak, testVector.ciphertext, plaintext, testVector.plaintext)
			}
		})
	}
}

// These are for testing long inputs, which are not in the sandard test vectors
func TestLong(t *testing.T) {
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(36, 16, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := "xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyal"

	ciphertext, err := ff1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if plaintext != decrypted {
		t.Fatalf("Long Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
	}
}

// Regression test for issue 14: https://github.com/capitalone/fpe/issues/14
func TestIssue14(t *testing.T) {
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("D8E7920AFA330A73")

	ff1, err := NewCipher(2, 8, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := "11111010"

	ciphertext, err := ff1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if plaintext != decrypted {
		t.Fatalf("Issue 14 Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
	}
}

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyz"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestConcurrentEncrypt(t *testing.T) {
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("D8E7920AFA330A73")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(36, 16, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		randString := generateRandomString(9)
		wg.Add(1)
		go func() {
			defer wg.Done()
			encrypted, err := ff1.Encrypt(randString)
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := ff1.Decrypt(encrypted)
			if err != nil {
				t.Fatal(err)
			}

			if randString != decrypted {
				t.Fatalf("got %q decrypted, want %q", decrypted, randString)
			}
		}()
	}

	wg.Wait()
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Encrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := "0123456789"

	// Call the encryption function on an example test vector
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	fmt.Println(ciphertext)
	// Output: 2433477484
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Decrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	ciphertext := "2433477484"

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	// Output: 0123456789
}

func BenchmarkNewCipher(b *testing.B) {
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

			b.ResetTimer()

			// 16 is an arbitrary number for maxTlen
			for n := 0; n < b.N; n++ {
				NewCipher(testVector.radix, 16, key, tweak)
			}
		})
	}
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

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Encrypt(testVector.plaintext)
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

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Decrypt(testVector.ciphertext)
			}
		})
	}
}

// This benchmark is for the end-to-end NewCipher, Encryption, Decryption process
// Similar to the examples
func BenchmarkE2ESample7(b *testing.B) {
	testVector := testVectors[6]
	key, err := hex.DecodeString(testVector.key)
	if err != nil {
		b.Fatalf("Unable to decode hex key: %v", testVector.key)
	}

	tweak, err := hex.DecodeString(testVector.tweak)
	if err != nil {
		b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		// 16 is an arbitrary number for maxTlen
		ff1, err := NewCipher(testVector.radix, 16, key, tweak)
		if err != nil {
			b.Fatalf("Unable to create cipher: %v", err)
		}

		ciphertext, err := ff1.Encrypt(testVector.plaintext)
		if err != nil {
			b.Fatalf("%v", err)
		}

		plaintext, err := ff1.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("%v", err)
		}

		_ = plaintext
	}
}

// BenchmarkEncryptLong is only for benchmarking the inner for loop code bath using a very large input to make d very large, making maxJ > 1
func BenchmarkEncryptLong(b *testing.B) {
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(36, 16, key, tweak)
	if err != nil {
		b.Fatalf("Unable to create cipher: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		ff1.Encrypt("xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwd")
	}
}
