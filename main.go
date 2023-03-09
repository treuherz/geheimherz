package main

import (
	"fmt"
	"io"
	"net"
	"os"
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
		return fmt.Errorf("identify: %w", err)
	}

	_, err = io.Copy(os.Stderr, conn)
	return err
}
