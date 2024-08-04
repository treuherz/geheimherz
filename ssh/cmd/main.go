package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/treuherz/geheimherz/ssh"
)

func main() {
	addr := ":22"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	
	if err = ssh.Handshake(conn); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}