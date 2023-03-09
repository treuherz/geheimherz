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

	r := bytes.NewReader(packet)

	kexInit, err := readByte(r)
	if err != nil {
		return msgKexInit{}, err
	}
	log.Println("read kexinit:", kexInit)

	// cookie
	err = discard(r, 16)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.kexAlgorithms, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.serverHostKeyAlgorithms, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.encryptionAlgorithmsCtoS, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.encryptionAlgorithmsStoC, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.macAlgorithmsCtoS, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.macAlgorithmsStoC, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.compressionAlgorithmsCtoS, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.compressionAlgorithmsStoC, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.languagesCtoS, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.languagesStoC, err = readNameList(r)
	if err != nil {
		return msgKexInit{}, err
	}

	msg.firstKexPacketFollows, err = readBoolean(r)
	if err != nil {
		return msgKexInit{}, err
	}

	// future extension
	err = discard(r, 4)
	if err != nil {
		return msgKexInit{}, err
	}

	return msg, nil
}

func readPacket(r io.Reader) ([]byte, error) {
	packetLength, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	paddingLengthRaw, err := readByte(r)
	if err != nil {
		return nil, err
	}
	paddingLength := uint32(paddingLengthRaw)

	if (4+1+packetLength+paddingLength)%8 != 0 {
		log.Println(4 + 1 + packetLength + paddingLength)
		return nil, errors.New("packet length before MAC must be divisible by 8")
	}

	payload, err := readBytes(r, packetLength-paddingLength-1)
	if err != nil {
		return nil, err
	}

	err = discard(r, paddingLength)
	if err != nil {
		return nil, err
	}

	log.Printf("received packet of length %d (plus %d of padding)", packetLength, paddingLength)

	return payload, nil
}

func discard(r io.Reader, n uint32) error {
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func readUint32(r io.Reader) (uint32, error) {
	raw := make([]byte, 4)
	_, err := r.Read(raw)
	if err != nil {
		return 0, err
	}

	v := uint32(raw[0])<<24 |
		uint32(raw[1])<<16 |
		uint32(raw[2])<<8 |
		uint32(raw[3])
	return v, nil
}

func readByte(r io.Reader) (byte, error) {
	raw := make([]byte, 1)
	_, err := r.Read(raw)
	if err != nil {
		return 0, err
	}

	return raw[0], nil
}

func readBytes(r io.Reader, len uint32) ([]byte, error) {
	raw := make([]byte, len)
	_, err := r.Read(raw)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func readNameList(r io.Reader) ([]string, error) {
	length, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	raw, err := readBytes(r, length)
	split := strings.Split(string(raw), ",")

	return split, nil
}

func readBoolean(r io.Reader) (bool, error) {
	b, err := readByte(r)
	if err != nil {
		return false, err
	}

	return b != 0, nil
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
