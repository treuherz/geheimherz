package main

import (
	"bytes"
	"crypto/rand"
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

type MessageID uint8

const (
	MessageDisconnect              MessageID = 1
	MessageIgnore                  MessageID = 2
	MessageUnimplemented           MessageID = 3
	MessageDebug                   MessageID = 4
	MessageServiceRequest          MessageID = 5
	MessageServiceAccept           MessageID = 6
	MessageKexinit                 MessageID = 20
	MessageNewkeys                 MessageID = 21
	MessageUserauthRequest         MessageID = 50
	MessageUserauthFailure         MessageID = 51
	MessageUserauthSuccess         MessageID = 52
	MessageUserauthBanner          MessageID = 53
	MessageGlobalRequest           MessageID = 80
	MessageRequestSuccess          MessageID = 81
	MessageRequestFailure          MessageID = 82
	MessageChannelOpen             MessageID = 90
	MessageChannelOpenConfirmation MessageID = 91
	MessageChannelOpenFailure      MessageID = 92
	MessageChannelWindowAdjust     MessageID = 93
	MessageChannelData             MessageID = 94
	MessageChannelExtendedData     MessageID = 95
	MessageChannelEOF              MessageID = 96
	MessageChannelClose            MessageID = 97
	MessageChannelRequest          MessageID = 98
	MessageChannelSuccess          MessageID = 99
	MessageChannelFailure          MessageID = 100
)

func connect(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	log.Printf("%s <-> %s", conn.LocalAddr(), conn.RemoteAddr())

	_, err = conn.Write([]byte("SSH-2.0-gossh_1.0b\r\n"))
	if err != nil {
		return fmt.Errorf("send id: %w", err)
	}

	serverID, err := readUntil(conn, '\n')
	if err != nil {
		return fmt.Errorf("recv id: %w", err)
	}
	log.Println("recv ID:", strings.TrimSuffix(string(serverID), "\r"))

	serverKexInit, err := readKexInit(conn)
	if err != nil {
		return fmt.Errorf("recv kexinint: %w", err)
	}

	log.Printf("recv kexinit %#v", serverKexInit)

	clientKexInit := msgKexInit{
		kexAlgorithms:             []string{"curve25519-sha256"},
		serverHostKeyAlgorithms:   []string{"ssh-ed25519"},
		encryptionAlgorithmsCtoS:  []string{"aes256-ctr"},
		encryptionAlgorithmsStoC:  []string{"aes256-ctr"},
		macAlgorithmsCtoS:         []string{"hmac-sha2-256"},
		macAlgorithmsStoC:         []string{"hmac-sha2-256"},
		compressionAlgorithmsCtoS: []string{"none"},
		compressionAlgorithmsStoC: []string{"none"},
		languagesCtoS:             []string{},
		languagesStoC:             []string{},
		firstKexPacketFollows:     false,
	}

	log.Printf("send kexinit %#v", clientKexInit)
	err = writeKexInit(conn, clientKexInit)
	if err != nil {
		return fmt.Errorf("send client kexinint: %w", err)
	}

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

	id := MessageID(r.readByte())
	if id != MessageKexinit {
		return msgKexInit{}, fmt.Errorf("wrong message ID: %d", id)
	}

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

	return msg, r.Err()
}

func writeKexInit(conn io.Writer, msg msgKexInit) error {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)

	w.writeByte(byte(MessageKexinit))

	// cookie
	w.copyN(rand.Reader, 16)

	w.writeNameList(msg.kexAlgorithms)
	w.writeNameList(msg.serverHostKeyAlgorithms)
	w.writeNameList(msg.encryptionAlgorithmsCtoS)
	w.writeNameList(msg.encryptionAlgorithmsStoC)
	w.writeNameList(msg.macAlgorithmsCtoS)
	w.writeNameList(msg.macAlgorithmsStoC)
	w.writeNameList(msg.compressionAlgorithmsCtoS)
	w.writeNameList(msg.compressionAlgorithmsStoC)
	w.writeNameList(msg.languagesCtoS)
	w.writeNameList(msg.languagesStoC)
	w.writeBoolean(msg.firstKexPacketFollows)

	// future extension
	w.writeUint32(0)

	return writePacket(conn, buf.Bytes())
}

func readPacket(conn io.Reader) ([]byte, error) {
	r := NewReader(conn)

	packetLength := r.readUint32()

	paddingLengthRaw := r.readByte()
	paddingLength := uint32(paddingLengthRaw)

	if (4+packetLength)%8 != 0 {
		return nil, errors.New("packet length before MAC must be divisible by 8")
	}

	payload := r.readBytes(packetLength - paddingLength - 1)

	r.discard(paddingLength)

	// TODO: MAC

	if err := r.Err(); err != nil {
		return nil, err
	}
	log.Printf("received packet of length %d (incl %d of padding)", packetLength, paddingLength)

	return payload, nil
}

func writePacket(conn io.Writer, payload []byte) error {
	w := NewWriter(conn)

	// TODO: Randomise padding length
	paddingLength := 4
	paddingRemainder := (paddingLength + len(payload) + 1 + 4) % 8
	if paddingRemainder > 0 {
		paddingLength += 8 - paddingRemainder
	}
	packetLength := paddingLength + len(payload) + 1

	w.writeUint32(uint32(packetLength))
	w.writeByte(uint8(paddingLength))
	w.writeBytes(payload)
	w.copyN(rand.Reader, int64(paddingLength))

	// TODO: MAC

	log.Printf("sent packet of length %d (incl %d of padding)", packetLength, paddingLength)

	return w.Err()
}
