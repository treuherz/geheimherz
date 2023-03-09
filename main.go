package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	addr := ":22"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	fmt.Println(connect(addr))
}

func connect(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	_, err = conn.Write([]byte("SSH-2.0-gossh_1.0b\r\n"))
	if err != nil {
		return fmt.Errorf("send id: %w", err)
	}

	read, err := readUntil(conn, '\n')
	if err != nil {
		return fmt.Errorf("recv id: %w", err)
	}
	fmt.Println("server sent ID:", strings.TrimSuffix(read, "\r"))

	_, err = io.Copy(os.Stderr, conn)
	return err
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
