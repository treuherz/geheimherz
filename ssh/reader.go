package ssh

import (
	"bytes"
	"io"
	"math/big"
	"strings"
)

type reader struct {
	rd  io.Reader
	err error
}

func NewReader(rd io.Reader) reader {
	return reader{rd: rd}
}

func (r *reader) read(b []byte) int {
	if r.err != nil {
		return 0
	}

	n, err := r.rd.Read(b)
	if err != nil {
		r.err = nil
	}

	return n
}

func (r *reader) Err() error {
	return r.err
}

func (r *reader) readUint32() uint32 {
	raw := make([]byte, 4)
	_ = r.read(raw)

	v := uint32(raw[0])<<8*3 |
		uint32(raw[1])<<8*2 |
		uint32(raw[2])<<8 |
		uint32(raw[3])
	return v
}

func (r *reader) readUint64() uint64 {
	raw := make([]byte, 8)
	_ = r.read(raw)

	v := uint64(raw[0])<<8*7 |
		uint64(raw[1])<<8*6 |
		uint64(raw[2])<<8*5 |
		uint64(raw[3])<<8*4 |
		uint64(raw[4])<<8*3 |
		uint64(raw[5])<<8*2 |
		uint64(raw[6])<<8*1 |
		uint64(raw[7])

	return v
}

func (r *reader) readMpint() *big.Int {
	length := r.readUint32()
	raw := make([]byte, length)
	_ = r.read(raw)

	i := new(big.Int)
	if len(raw) > 0 {
		sign := 1
		if raw[0]&0x80 != 0 {
			sign = -1
			twosComplement(raw)
		}

		i.SetBytes(raw)
		if sign == -1 {
			i.Neg(i)
		}
	}

	return i
}

func (r *reader) readByte() byte {
	raw := make([]byte, 1)
	_ = r.read(raw)
	return raw[0]
}

func (r *reader) readBytes(len uint32) []byte {
	raw := make([]byte, len)
	_ = r.read(raw)
	return raw
}

func (r *reader) readNameList() []string {
	length := r.readUint32()

	raw := r.readBytes(length)
	split := strings.Split(string(raw), ",")

	return split
}

func (r *reader) readBoolean() bool {
	b := r.readByte()
	return b != 0
}

func (r *reader) discard(n uint32) {
	if r.err != nil {
		return
	}

	_, err := io.CopyN(io.Discard, r.rd, int64(n))
	if err != nil {
		r.err = err
	}
}

func (r *reader) readString() []byte {
	length := r.readUint32()

	b := r.readBytes(length)

	return b
}

func readUntil(r io.Reader, delim byte) ([]byte, error) {
	buf := bytes.Buffer{}

	s := make([]byte, 1)
	_, err := r.Read(s)
	if err != nil {
		return nil, err
	}

	for s[0] != delim {
		buf.Write(s)

		_, err := r.Read(s)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
