package fpe

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {

	testSpec := []struct {
		radix   uint64
		intv    *big.Int
		numeral []uint16
	}{
		{
			10,
			big.NewInt(100),
			[]uint16{1, 0, 0},
		},
		{
			65536,
			big.NewInt(0).Exp(big.NewInt(65536), big.NewInt(7), nil),
			[]uint16{1, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	for idx, spec := range testSpec {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			v, err := Num(spec.numeral, spec.radix)
			if err != nil {
				t.Fatalf("error in Num: %s", err)
			}
			if v.Cmp(spec.intv) != 0 {
				t.Fatalf("expected %v got %v", spec.intv, &v)
			}
			r := make([]uint16, len(spec.numeral))
			Str(&v, r, spec.radix)
			if !reflect.DeepEqual(spec.numeral, r) {
				t.Fatalf("Encode numeral incorrect: %v", r)
			}

		})
	}
}

func TestEncodeError(t *testing.T) {

	testSpec := []struct {
		radix   uint64
		intv    *big.Int
		numeral []uint16
	}{
		{
			10,
			big.NewInt(100),
			[]uint16{10, 0, 0},
		},
		{
			65537,
			big.NewInt(0).Exp(big.NewInt(65537), big.NewInt(7), nil),
			[]uint16{1, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	for idx, spec := range testSpec {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			_, err := Num(spec.numeral, spec.radix)
			if err == nil {
				t.Fatalf("expected error in Num")
			}
		})
	}
}

func TestDecodeError(t *testing.T) {

	testSpec := []struct {
		radix   uint64
		intv    *big.Int
		numeral []uint16
	}{
		{
			10,
			big.NewInt(100),
			[]uint16{1, 0, 0},
		},
		{
			65537,
			big.NewInt(0).Exp(big.NewInt(65537), big.NewInt(7), nil),
			[]uint16{1, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	for idx, spec := range testSpec {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			r := make([]uint16, 2)	
			_,err := Str(spec.intv, r, spec.radix)
			if err == nil {
				t.Fatalf("expected error in Str")
			}
		})
	}
}
