package main

import (
	"math/big"
	"fmt"
)

func num(s []uint16, radix uint64) (*big.Int, *big.Int, error) {
	var big_radix, max, bv, x big.Int
	if radix > 65536 {
		return nil, nil, fmt.Errorf("Radix (%d) too big: max supported radix is 65536", radix)
	}

	maxv := uint16(radix - 1)
	big_radix.SetUint64(uint64(radix))
	max.SetInt64(1)

	for i, v := range s {
		if v > maxv {
			return nil, nil, fmt.Errorf("Value at %d out of range: got %d - expected 0..%d", i, v, maxv)
		}
		bv.SetUint64(uint64(v))
		x.Mul(&x, &big_radix)
		x.Add(&x, &bv)
		max.Mul(&max, &big_radix)
	}
	return &x, &max, nil
}

func str(x *big.Int, m int, radix uint64) []uint16 {
	r := make([]uint16, m)
	
	var big_radix, mod, v big.Int
	v.Set(x)
	big_radix.SetUint64(radix)
	for i := range r {
		v.DivMod(&v, &big_radix, &mod)
		r[m-i-1] = uint16(mod.Uint64())
	}
	return r
}

func main() {

	s := []uint16{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9}
	n,max,err := num(s,10)
	fmt.Println(n)
	fmt.Println(max)
	fmt.Println(err)

	v := str(n, len(s), 10)
	fmt.Println(v)
	fmt.Println(n)
}

