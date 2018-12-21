package fpe

import (
	"fmt"
	"reflect"
	"testing"
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
				t.Fatalf("Encode unexpectly succeeded: input '%s', alphabet '%s'", spec.input, spec.alphabet)
			}
		})
	}
}
