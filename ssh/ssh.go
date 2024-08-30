package ssh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"
)

type MessageID uint8

const (
	MessageDisconnect     MessageID = 1
	MessageIgnore         MessageID = 2
	MessageUnimplemented  MessageID = 3
	MessageDebug          MessageID = 4
	MessageServiceRequest MessageID = 5
	MessageServiceAccept  MessageID = 6

	MessageKexinit MessageID = 20
	MessageNewkeys MessageID = 21

	MessageUserauthRequest MessageID = 50
	MessageUserauthFailure MessageID = 51
	MessageUserauthSuccess MessageID = 52
	MessageUserauthBanner  MessageID = 53

	MessageGlobalRequest  MessageID = 80
	MessageRequestSuccess MessageID = 81
	MessageRequestFailure MessageID = 82

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

	// These are algorithm-specific
	MessageKexECDHInit  MessageID = 30
	MessageKexECDHReply MessageID = 31
)

func Handshake(conn net.Conn, serverKey ed25519.PublicKey) error {
	clientID := "SSH-2.0-geheimherz_0"
	_, err := conn.Write([]byte(clientID + "\r\n"))
	if err != nil {
		return fmt.Errorf("send id: %w", err)
	}

	serverIDBytes, err := readUntil(conn, '\n')
	if err != nil {
		return fmt.Errorf("recv id: %w", err)
	}
	serverID := strings.TrimSpace(string(serverIDBytes))
	log.Println("recv ID:", strings.TrimSuffix(serverID, "\r"))

	serverKexInitPacket, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("recv kexinit: %w", err)
	}
	serverKexInit, err := decodeKexInit(serverKexInitPacket)
	if err != nil {
		return fmt.Errorf("recv kexinint: %w", err)
	}

	log.Printf("recv kexinit %#v", serverKexInit)

	clientKexInit := buildClientKexInit()
	log.Printf("send kexinit %#v", clientKexInit)
	clientKexInitPacket := encodeKexInit(clientKexInit)
	err = writePacket(conn, clientKexInitPacket)
	if err != nil {
		return fmt.Errorf("send client kexinint: %w", err)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ephemeral ECDH key: %w", err)
	}

	ecdhKexInit, err := buildECDHKexInit(key.PublicKey())
	if err != nil {
		return fmt.Errorf("build ECDH kexinint: %w", err)
	}

	log.Printf("send ECDH kexinit %#v", ecdhKexInit)
	err = writePacket(conn, encodeECDHKexInit(ecdhKexInit))
	if err != nil {
		return fmt.Errorf("send ECDH kexinint: %w", err)
	}

	ecdhKexReplyPacket, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("recv ecdh kex reply: %w", err)
	}

	ecdhKexReply, err := decodeECDHKexReply(ecdhKexReplyPacket)
	if err != nil {
		return fmt.Errorf("decode kex reply: %w", err)
	}

	serverSentKey, err := decodeEd25519Key(bytes.NewReader(ecdhKexReply.K_S))
	if err != nil {
		return errors.New("decode server public key")
	}

	if !serverKey.Equal(serverSentKey) {
		return errors.New("server public key not recognised")
	}

	sharedSecret, err := computeSharedSecret(key, ecdhKexReply)
	if err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}

	if err := verifySignature(
		serverKey,
		ecdhKexReply,
		clientID,
		serverID,
		clientKexInitPacket,
		serverKexInitPacket,
		key,
		sharedSecret,
	); err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}

	log.Print("signature verified, shared key computed")

	conn.Close()
	return nil
}

func verifySignature(
	serverKey ed25519.PublicKey,
	reply msgECDHKexReply,
	clientID, serverID string,
	clientKexInit, serverKexInit []byte,
	clientKey *ecdh.PrivateKey,
	sharedSecret []byte,
) error {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)

	w.writeString([]byte(clientID))
	w.writeString([]byte(serverID))
	w.writeString(clientKexInit)
	w.writeString(serverKexInit)
	w.writeString(reply.K_S)
	w.writeString(clientKey.PublicKey().Bytes())
	w.writeString(reply.Q_S)
	w.writeMpint(new(big.Int).SetBytes(sharedSecret))

	if err := w.Err(); err != nil {
		return fmt.Errorf("build exchange hash: %w", err)
	}

	exchangeHash := sha256.Sum256(buf.Bytes())

	serverSig, err := decodeEd25519Sig(bytes.NewReader(reply.signature))
	if err != nil {
		return fmt.Errorf("decode server-sent signature: %w", err)
	}

	if !ed25519.Verify(serverKey, exchangeHash[:], serverSig) {
		return errors.New("couldn't verify signature")
	}

	return nil
}

func computeSharedSecret(key *ecdh.PrivateKey, reply msgECDHKexReply) ([]byte, error) {
	remote, err := ecdh.X25519().NewPublicKey(reply.Q_S)
	if err != nil {
		return nil, fmt.Errorf("parse host public key: %w", err)
	}

	return key.ECDH(remote)
}

func buildECDHKexInit(key *ecdh.PublicKey) (msgECDHKexInit, error) {
	return msgECDHKexInit{
		Q_C: key.Bytes(),
	}, nil
}

func buildClientKexInit() msgKexInit {
	msg := msgKexInit{
		Cookie:                [16]byte{},
		KexAlgs:               []string{"curve25519-sha256"},
		ServerHostKeyAlgs:     []string{"ssh-ed25519"},
		EncryptionAlgsCtoS:    []string{"aes256-ctr"},
		EncryptionAlgsStoC:    []string{"aes256-ctr"},
		MacAlgsCtoS:           []string{"hmac-sha2-256"},
		MacAlgsStoC:           []string{"hmac-sha2-256"},
		CompressionAlgsCtoS:   []string{"none"},
		CompressionAlgsStoC:   []string{"none"},
		LanguagesCtoS:         []string{},
		LanguagesStoC:         []string{},
		FirstKexPacketFollows: false,
	}

	rand.Read(msg.Cookie[:])
	return msg
}

type msgKexInit struct {
	ID                    MessageID `ssh:"20"`
	Cookie                [16]byte
	KexAlgs               []string
	ServerHostKeyAlgs     []string
	EncryptionAlgsCtoS    []string
	EncryptionAlgsStoC    []string
	MacAlgsCtoS           []string
	MacAlgsStoC           []string
	CompressionAlgsCtoS   []string
	CompressionAlgsStoC   []string
	LanguagesCtoS         []string
	LanguagesStoC         []string
	FirstKexPacketFollows bool
	Reserved              uint32
}

func scanPacket(r reader, msg any) error {
	typ := reflect.TypeOf(msg)
	if typ.Kind() != reflect.Ptr {
		return errors.New("msg must be a pointer")
	}
	if typ.Elem().Kind() != reflect.Struct {
		return errors.New("msg must be a pointer to a struct")
	}

	val := reflect.ValueOf(msg).Elem()
	for i := range val.NumField() {
		field := val.Field(i)
		if i == 0 {
			tag := typ.Elem().Field(i).Tag.Get("ssh")
			if tag == "" {
				return errors.New("no ssh tag found on field 0")
			}
			wantID, err := strconv.Atoi(tag)
			if err != nil {
				return errors.New("ssh tag must be a number")
			}

			if gotID := r.readByte(); gotID != byte(wantID) {
				return fmt.Errorf("wrong message ID: %d", gotID)
			}

			continue
		}

		switch field.Kind() {
		case reflect.Uint8:
			field.SetUint(uint64(r.readByte()))
		case reflect.Array:
			r.read(field.Slice(0, field.Len()).Bytes())
		case reflect.Slice:
			switch field.Type().Elem().Kind() {
			case reflect.Uint8:
				field.SetBytes(r.readString())
			case reflect.String:
				field.Set(reflect.ValueOf(r.readNameList()))
			default:
				return errors.New("unsupported slice type")
			}
		case reflect.Uint32:
			field.SetUint(uint64(r.readUint32()))
		case reflect.Uint64:
			field.SetUint(uint64(r.readUint64()))
		case reflect.Bool:
			field.SetBool(r.readBoolean())
		}
	}

	return r.Err()
}

func decodeKexInit(packet []byte) (msg msgKexInit, err error) {
	r := NewReader(bytes.NewReader(packet))
	err = scanPacket(r, &msg)
	return msg, err
}

func decodeECDHKexReply(packet []byte) (msgECDHKexReply, error) {
	var msg msgECDHKexReply

	r := NewReader(bytes.NewReader(packet))

	id := MessageID(r.readByte())
	if id != MessageKexECDHReply {
		return msgECDHKexReply{}, fmt.Errorf("wrong message ID: %d", id)
	}

	msg.K_S = r.readString()
	msg.Q_S = r.readString()
	msg.signature = r.readString()

	return msg, r.Err()
}

func encodeKexInit(msg msgKexInit) []byte {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)

	w.writeByte(byte(MessageKexinit))

	w.writeBytes(msg.Cookie[:])
	w.writeNameList(msg.KexAlgs)
	w.writeNameList(msg.ServerHostKeyAlgs)
	w.writeNameList(msg.EncryptionAlgsCtoS)
	w.writeNameList(msg.EncryptionAlgsStoC)
	w.writeNameList(msg.MacAlgsCtoS)
	w.writeNameList(msg.MacAlgsStoC)
	w.writeNameList(msg.CompressionAlgsCtoS)
	w.writeNameList(msg.CompressionAlgsStoC)
	w.writeNameList(msg.LanguagesCtoS)
	w.writeNameList(msg.LanguagesStoC)
	w.writeBoolean(msg.FirstKexPacketFollows)

	// future extension
	w.writeUint32(0)
	payload := buf.Bytes()
	return payload
}

type msgECDHKexInit struct {
	Q_C []byte
}

type msgECDHKexReply struct {
	K_S       []byte
	Q_S       []byte
	signature []byte
}

func encodeECDHKexInit(msg msgECDHKexInit) []byte {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)

	w.writeByte(byte(MessageKexECDHInit))
	w.writeString(msg.Q_C)

	payload := buf.Bytes()
	return payload
}

func decodeEd25519Key(r io.Reader) (ed25519.PublicKey, error) {
	rr := NewReader(r)
	prefix := rr.readString()
	if !bytes.Equal(prefix, []byte("ssh-ed25519")) {
		return nil, errors.New("wrong prefix")
	}

	k := rr.readString()
	return k, nil
}

func decodeEd25519Sig(r io.Reader) ([]byte, error) {
	rr := NewReader(r)
	prefix := rr.readString()
	if !bytes.Equal(prefix, []byte("ssh-ed25519")) {
		return nil, errors.New("wrong prefix")
	}

	sig := rr.readString()
	return sig, nil
}

func readMessage(conn io.Reader) (raw []byte, msg any, err error) {
	raw, err = readPacket(conn)
	if err != nil {
		return raw, nil, err
	}
	
	r := NewReader(bytes.NewReader(raw))
	
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
