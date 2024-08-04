package main

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWriteMPInt(t *testing.T) {
	tests := []struct {
		vHex string
		want []byte
	}{
		{
			vHex: "0",
			want: []byte{0x0, 0x0, 0x0, 0x0},
		},
		{
			vHex: "9a378f9b2e332a7",
			want: []byte{0x0, 0x0, 0x0, 0x8, 0x9, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7},
		},
		{
			vHex: "80",
			want: []byte{0x0, 0x0, 0x0, 0x02, 0x0, 0x80},
		},
		{
			vHex: "-1234",
			want: []byte{0x0, 0x0, 0x0, 0x2, 0xed, 0xcc},
		},
		{
			vHex: "-deadbeef",
			want: []byte{0x0, 0x0, 0x0, 0x5, 0xff, 0x21, 0x52, 0x41, 0x11},
		},
	}

	for _, test := range tests {
		t.Run(test.vHex, func(t *testing.T) {
			buf := &bytes.Buffer{}
			w := NewWriter(buf)

			bi, ok := new(big.Int).SetString(test.vHex, 16)
			if !ok {
				t.Fatal("parse hex")
			}

			w.writeMpint(bi)

			if err := w.Err(); err != nil {
				t.Fatal("write error:", err)
			}

			if d := cmp.Diff(test.want, buf.Bytes()); d != "" {
				t.Error(d)
			}
		})
	}
}
