package main

import (
	"bytes"
	"errors"
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

	serverID, err := readUntil(conn, '\n')
	if err != nil {
		return fmt.Errorf("recv id: %w", err)
	}
	log.Println("server sent ID:", strings.TrimSuffix(string(serverID), "\r"))

	serverKexInit, err := readKexInit(conn)
	if err != nil {
		return fmt.Errorf("server kexinint: %w", err)
	}

	log.Printf("%#v", serverKexInit)

	_, err = io.Copy(os.Stderr, conn)
	return err
}

type msgKexInit struct {
	kexAlgorithms             []string
	serverHostKeyAlgorithms   []string
	encryptionAlgorithmsCtoS  []string
	encryptionAlgorithmsStoC  []string
	macAlgorithmsCtoS         []string
	macAlgorithmsStoC         []string
	compressionAlgorithmsCtoS []string
	compressionAlgorithmsStoC []string
	languagesCtoS             []string
	languagesStoC             []string
	firstKexPacketFollows     bool
}

func readKexInit(conn io.Reader) (msg msgKexInit, err error) {
	packet, err := readPacket(conn)
	if err != nil {
		return msgKexInit{}, fmt.Errorf("read packet: %w", err)
	}

	r := NewReader(bytes.NewReader(packet))

	kexInit := r.readByte()
	log.Println("read kexinit:", kexInit)

	// cookie
	r.discard(16)

	msg.kexAlgorithms = r.readNameList()
	msg.serverHostKeyAlgorithms = r.readNameList()
	msg.encryptionAlgorithmsCtoS = r.readNameList()
	msg.encryptionAlgorithmsStoC = r.readNameList()
	msg.macAlgorithmsCtoS = r.readNameList()
	msg.macAlgorithmsStoC = r.readNameList()
	msg.compressionAlgorithmsCtoS = r.readNameList()
	msg.compressionAlgorithmsStoC = r.readNameList()
	msg.languagesCtoS = r.readNameList()
	msg.languagesStoC = r.readNameList()
	msg.firstKexPacketFollows = r.readBoolean()

	// future extension
	r.discard(4)

	if err := r.Err(); err != nil {
		return msg, err
	}

	return msg, nil
}

func readPacket(conn io.Reader) ([]byte, error) {
	r := NewReader(conn)

	packetLength := r.readUint32()

	paddingLengthRaw := r.readByte()
	paddingLength := uint32(paddingLengthRaw)

	if (4+1+packetLength+paddingLength)%8 != 0 {
		log.Println(4 + 1 + packetLength + paddingLength)
		return nil, errors.New("packet length before MAC must be divisible by 8")
	}

	payload := r.readBytes(packetLength - paddingLength - 1)

	r.discard(paddingLength)

	if err := r.Err(); err != nil {
		return nil, err
	}
	log.Printf("received packet of length %d (plus %d of padding)", packetLength, paddingLength)

	return payload, nil
}
