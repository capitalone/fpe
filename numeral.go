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
func Str(x *big.Int, r []uint16, radix uint64) ([]uint16,error) {

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

// EncodeNum constructs a big Int that represents the ordinal values of string s 
// with respect to the alphabet built into the codec.
func EncodeNum(s string, c Codec) (*big.Int, error) {
	numeral, err := c.Encode(s)
	if err != nil {
		return nil, err
	}
	v, err := Num(numeral,uint64(c.Radix()))
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// DecodeNum constructs a string from the ordinals encoded in two big Ints.
// len_a and len_b are the number of characters that should be built from the corresponding big Ints. 
func DecodeNum(a *big.Int, len_a int, b *big.Int, len_b int, c Codec) (string,error) {
	ret := make([]uint16,len_a+len_b)
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

