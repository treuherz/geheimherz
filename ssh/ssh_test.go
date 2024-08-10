package ssh_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"

	glssh "github.com/gliderlabs/ssh"
	"github.com/treuherz/geheimherz/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func TestClientHandshake(t *testing.T) {
	addr, serverKey := testingServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	err = ssh.Handshake(conn, serverKey)
	if err != nil {
		t.Error(err)
	}
}

func testingKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	return pub, prv
}

func testingServer(t *testing.T) (addr string, key ed25519.PublicKey) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	pub, prv := testingKeypair(t)

	signer, err := gossh.NewSignerFromSigner(prv)
	if err != nil {
		t.Fatal(err)
	}

	srv := &glssh.Server{
		Handler: func(session glssh.Session) {
			session.Write([]byte("you're in"))
		},
		HostSigners: []glssh.Signer{signer},
		Version:     "testing",
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	go func() {
		if err := srv.Serve(l); err != nil {
			if errors.Is(err, glssh.ErrServerClosed) {
				return
			}
			t.Error(err)
		}
	}()

	return l.Addr().String(), pub
}
