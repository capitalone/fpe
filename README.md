[![Godoc](https://godoc.org/github.com/capitalone/fpe?status.svg)](http://godoc.org/github.com/capitalone/fpe) [![Build Status](https://travis-ci.org/capitalone/fpe.svg?branch=master)](https://travis-ci.org/capitalone/fpe) [![Go Report Card](https://goreportcard.com/badge/github.com/capitalone/fpe)](https://goreportcard.com/report/github.com/capitalone/fpe) [![Sourcegraph](https://sourcegraph.com/github.com/capitalone/fpe/-/badge.svg)](https://sourcegraph.com/github.com/capitalone/fpe?badge) [![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# fpe - Format Preserving Encryption Implementation in Go

An implementation of the NIST approved Format Preserving Encryption (FPE) FF1 and FF3 algorithms in Go.

[NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This follows the FF1 and FF3 schemes for Format Preserving Encryption outlined in the NIST Recommendation, released in March 2016. For FF1, it builds on and formalizes (differing from but remaining mathematically equivalent to) the FFX-A10 scheme by Bellare, Rogaway and Spies as defined [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf) and [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf). For FF3, it formalizes the BPS scheme.

A note about FF3: There was some [recent cryptanalysis](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) about the FF3 algorithm that is important to review. NIST has concluded that FF3 is no longer suitable as a general-purpose FPE method.

A note about FF2: FF2 was originally NOT recommended by NIST, but it is under review again as DFF. You can read about it [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/dff/dff-ff2-fpe-scheme-update.pdf).

## Testing

There are some official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for both FF1 and FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation with all test vectors from the NIST link above, run the built-in tests:

  1. `go test -v github.com/capitalone/fpe/ff1`
  2. `go test -v github.com/capitalone/fpe/ff3`

To run only benchmarks:

  1. `go test -v -bench=. -run=NONE github.com/capitalone/fpe/ff1`
  2. `go test -v -bench=. -run=NONE github.com/capitalone/fpe/ff3`

## Example Usage

The example code below can help you get started. Copy it into a file called `main.go`, and run it with `go run main.go`.

```golang
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/capitalone/fpe/ff1"
)

// panic(err) is just used for example purposes.
func main() {
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

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := ff1.NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := "123456789"

	// Call the encryption function on an example SSN
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original:", original)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)
}
```

## Usage notes

There is a [FIPS Document](http://csrc.nist.gov/groups/STM/cmvp/documents/fips140-2/FIPS1402IG.pdf) that contains`Requirements for Vendor Affirmation of SP 800-38G` on page 155.

There are some patent related details for FF1 and FF3 as Voltage Security (which was acquired by what is now HP Enterprise) originally developed FFX, which became FF1. They provided NIST with a [Letter of Assurance](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-voltage-ip.pdf) on the matter.

It can be used as part of sensitive data tokenization, especially in regards to PCI and cryptographically reversible tokens. This implementation does not provide any gaurantees regarding PCI DSS or other validation.

It's important to note that, as with any cryptographic package, managing and protecting the key appropriately to your situation is crucial. This package does not provide any guarantees regarding the key in memory.

## Implementation Notes

Overall, this was originally written with the following goals:

  * Be idiomatic as possible from a Go language, package, and interface perspective
  * Follow the algorithm as outlined in the NIST recommendation as closely as possible
  * Attempt to be a reference implementation since one does not exist yet

As such, it was not necessarily written from a performance perspective.

As of Go 1.8.1, the standard library's [math/big](https://golang.org/pkg/math/big/) package did not support radices/bases higher than 36. As such, this initial release only supports base 36 strings, which can contain numeric digits 0-9 or lowercase alphabetic characters a-z.

Base 62 support involves simple changes to the `math/big` package; hopefully that can be contributed soon to `math/big` soon. Creating a modified `math/big` sub-package just for 4 lines of changed code seemed like overkill, hence `math/big` being updated is a better solution long term. Ideally, it can be developed further into arbitrary alphabet and base support, which may alleviate the need to use a new Go version where `math/big` has the base 62 support.

The only cryptographic primitive used for FF1 and FF3 is AES. This package uses Go's standard library's `crypto/aes` package for this. Note that while it technically uses AES-CBC mode, in practice it almost always is meant to act on a single-block with an IV of 0, which is effectively ECB mode. AES is also the only block cipher function that works at the moment, and the only allowed block cipher to be used for FF1/FF3, as per the spec.

In the spec, it says that the radix and minimum length (minLen) of the message should be such that `radix^minLen >= 100`. In Appendix A, it mentions this is to prevent a generic MITM against the Feistel structure, but for better security, radix^minLen >= 1,000,000. In `ff1.go` and `ff3.go` there is a `const` called `FEISTEL_MIN` that can be changed to a sufficient value (like 1,000,000), but by default, it only follows the bare spec.

Regarding how the "tweak" is used as input: I interpreted the spec as setting the tweak in the initial `NewCipher` call, instead of in each `Encrypt` and `Decrypt` call. In one sense, it is similar to passing an IV or nonce once when creating an encryptor object. It's likely that this can be modified to do it in each `Encrypt`/`Decrypt` call, if that is more applicable to what you are building.

## Using a Hardware Security Module (HSM)

The FF1 code can be modified to work with an HSM as well. Modify the `ff1.go` `ciph()` function to make an AES-CBC call to an HSM using the PKCS11 interface with mechanism `CKM_AES_CBC`. Instead of passing the key through, you will pass a label to the HSM object that has the key. Make sure not to use `CKM_AES_CBC_PAD` as the mechanism, you have to use `CKM_AES_CBC`!

Unfortunately, because FF3 reverses the key as part of the algorithm, it is not as straightforward to use FF3 with an HSM unless you can generate the reverse of a key in the HSM itself and use that.

A popular PKCS11 package for Go is [github.com/miekg/pkcs11](https://github.com/miekg/pkcs11)

Hopefully, the `ff1.Cipher` `cbcEncryptor` can be more of an overridable interface such that a customized `cipher.BlockMode` can be crafted that internally calls the HSM.

## Existing Implementations

Based on searching GitHub and the Internet, there are no known reference implementations for either algorithm.

An [existing Go implementation](https://github.com/Roasbeef/perm-crypt) based on the earlier FFX spec was already created, but the implementation differs slightly from the final NIST recommendation. Further, that implementation doesn't work for higher radices or long strings as it doesn't use `math/big` (big integers).

There is a [Java implementation](https://sourceforge.net/projects/format-preserving-encryption/) that was also used for testing and comparison while developing this, as it was the only other fully working implementation available.

## Contributors

We welcome your interest in Capital One’s Open Source Projects (the “Project”). Any Contributor to the project must accept and sign a CLA indicating agreement to the license terms. Except for the license granted in this CLA to Capital One and to recipients of software distributed by Capital One, you reserve all right, title, and interest in and to your contributions; this CLA does not impact your rights to use your own contributions for any other purpose.

[Link to Individual CLA](https://docs.google.com/forms/d/19LpBBjykHPox18vrZvBbZUcK6gQTj7qv1O5hCduAZFU/viewform)

[Link to Corporate CLA](https://docs.google.com/forms/d/e/1FAIpQLSeAbobIPLCVZD_ccgtMWBDAcN68oqbAJBQyDTSAQ1AkYuCp_g/viewform)

This project adheres to the [Open Source Code of Conduct](https://developer.capitalone.com/single/code-of-conduct/). By participating, you are expected to honor this code.
