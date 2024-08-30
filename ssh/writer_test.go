package ssh

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWriteMPInt(t *testing.T) {
	for _, test := range mpintTests {
		t.Run(test.hex, func(t *testing.T) {
			buf := &bytes.Buffer{}
			w := NewWriter(buf)

			bi, ok := new(big.Int).SetString(test.hex, 16)
			if !ok {
				t.Fatal("parse hex")
			}

			w.writeMpint(bi)

			if err := w.Err(); err != nil {
				t.Fatal("write error:", err)
			}

			if d := cmp.Diff(test.bytes, buf.Bytes()); d != "" {
				t.Error(d)
			}
		})
	}
}
