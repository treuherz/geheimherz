package main

import (
	"io"
	"strings"
)

type writer struct {
	wr  io.Writer
	err error
}

func NewWriter(wr io.Writer) writer {
	return writer{wr: wr}
}

func (w *writer) write(b []byte) int {
	if w.err != nil {
		return 0
	}

	n, err := w.wr.Write(b)
	if err != nil {
		w.err = nil
	}

	return n
}

func (w *writer) Err() error {
	return w.err
}

func (w *writer) writeUint32(v uint32) {
	raw := make([]byte, 4)

	raw[0] = byte(v >> 24)
	raw[1] = byte(v >> 16)
	raw[2] = byte(v >> 8)
	raw[3] = byte(v)

	_ = w.write(raw)
}

func (w *writer) writeByte(v byte) {
	raw := []byte{v}
	_ = w.write(raw)
}

func (w *writer) writeBytes(v []byte) {
	_ = w.write(v)
}

func (w *writer) writeNameList(v []string) {
	joined := strings.Join(v, ",")

	w.writeUint32(uint32(len(joined)))
	w.writeBytes([]byte(joined))
}

func (w *writer) writeBoolean(v bool) {
	var b byte
	if v {
		b = 1
	}
	w.writeByte(b)
}

func (w *writer) copyN(r io.Reader, n int64) {
	if w.err != nil {
		return
	}

	_, err := io.CopyN(w.wr, r, n)
	if err != nil {
		w.err = err
	}
}
