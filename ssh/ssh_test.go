package ssh_test

import (
	"context"
	"net"

	glssh "github.com/gliderlabs/ssh"
	"github.com/treuherz/geheimherz/ssh"

	"testing"
)

func TestClientHandshake(t *testing.T) {
	addr := testingServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	err = ssh.Handshake(conn)
	if err != nil {
		t.Error(err)
	}
}

func testingServer(t *testing.T) string {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	srv := &glssh.Server{}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	go func() {
		t.Error(srv.Serve(l))
	}()

	return l.Addr().String()
}
