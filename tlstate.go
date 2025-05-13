package TLState

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/41Baloo/TLState/byteBuffer"
	ringBuffer "github.com/panjf2000/gnet/v2/pkg/pool/ringbuffer"
	"github.com/rs/zerolog/log"
)

var (
	ErrReadDuringHandshake         = errors.New("cannot read application data before completing handshake")
	ErrTLS13NotSupported           = errors.New("client does not support TLS 1.3")
	ErrCiphersNotSupported         = errors.New("client does not support our given ciphers")
	ErrCipherNotImplemented        = errors.New("the selected cipher in Config is not implemented yet")
	ErrNoValidKeyShare             = errors.New("no valid keyshare found in clientHello")
	ErrClientFinishVerifyMissmatch = errors.New("client finished verify data and our verify data mismatch")
)

type HandshakeState uint8

const (
	HandshakeStateInitial HandshakeState = iota
	HandshakeStateClientHelloDone
	HandshakeStateServerHelloDone
	HandshakeStateWaitClientFinished
	HandshakeStateDone
)

// We extensively use this as a "hack", whenever a function returns this type, under the hood
// a byteBuffer is instead being written to. This helps us avoid heap allocations. The value of
// this type tells us wether our operation succeeded or not / if anything has been written
// to the byteBuffer or not.
type ResponseState uint8

const (
	None      ResponseState = iota // Nothing was written, no need to respond
	Responded                      // Response data was flushed to outgoing, send it to receiver
)

// Represents the state of a TLS 1.3 connection
type TLState struct {
	Config *Config

	incoming          *ringBuffer.RingBuffer
	handshakeMessages *byteBuffer.ByteBuffer

	privateKey    []byte
	publicKey     []byte
	peerPublicKey []byte

	handshakeSecret                []byte
	clientHandshakeTrafficSecret   []byte
	serverHandshakeTrafficSecret   []byte
	clientApplicationTrafficSecret []byte
	serverApplicationTrafficSecret []byte

	serverHandshakeKey []byte
	serverHandshakeIV  []byte
	clientHandshakeKey []byte
	clientHandshakeIV  []byte

	serverApplicationKey []byte
	serverApplicationIV  []byte
	clientApplicationKey []byte
	clientApplicationIV  []byte

	serverRecordCount uint64
	clientRecordCount uint64

	handshakeState HandshakeState

	cipher       CipherSuite
	clientCipher cipher.AEAD
	serverCipher cipher.AEAD

	clientRandom []byte
	sessionID    []byte
}

var pool = &sync.Pool{
	New: func() interface{} {
		return &TLState{
			incoming:          ringBuffer.Get(),
			handshakeMessages: byteBuffer.Get(),

			privateKey:    make([]byte, 32),
			publicKey:     make([]byte, 0, 32),
			peerPublicKey: make([]byte, 0, 32),

			handshakeSecret:                make([]byte, 0, 32),
			clientHandshakeTrafficSecret:   make([]byte, 0, 32),
			serverHandshakeTrafficSecret:   make([]byte, 0, 32),
			clientApplicationTrafficSecret: make([]byte, 0, 32),
			serverApplicationTrafficSecret: make([]byte, 0, 32),

			serverHandshakeKey:   make([]byte, 0, 16),
			serverHandshakeIV:    make([]byte, 0, 12),
			clientHandshakeKey:   make([]byte, 0, 16),
			clientHandshakeIV:    make([]byte, 0, 12),
			serverApplicationKey: make([]byte, 0, 16),
			serverApplicationIV:  make([]byte, 0, 12),
			clientApplicationKey: make([]byte, 0, 16),
			clientApplicationIV:  make([]byte, 0, 12),

			clientRandom: make([]byte, 32),
			sessionID:    make([]byte, 0, 32),
		}
	},
}

func Get() (*TLState, error) {
	state := pool.Get().(*TLState)

	_, err := io.ReadFull(rand.Reader, state.privateKey)
	if err != nil {
		pool.Put(state)
		return nil, err
	}

	state.publicKey, err = curve25519.X25519(state.privateKey, curve25519.Basepoint)
	if err != nil {
		pool.Put(state)
		return nil, err
	}

	return state, nil
}

func Put(t *TLState) {

	t.incoming.Reset()
	t.handshakeMessages.Reset()

	t.publicKey = t.publicKey[:0]
	t.handshakeState = HandshakeStateInitial

	t.peerPublicKey = t.peerPublicKey[:0]

	t.handshakeSecret = t.handshakeSecret[:0]
	t.clientHandshakeTrafficSecret = t.clientHandshakeTrafficSecret[:0]
	t.serverHandshakeTrafficSecret = t.serverHandshakeTrafficSecret[:0]
	t.clientApplicationTrafficSecret = t.clientApplicationTrafficSecret[:0]
	t.serverApplicationTrafficSecret = t.serverApplicationTrafficSecret[:0]

	t.serverHandshakeKey = t.serverHandshakeKey[:0]
	t.serverHandshakeIV = t.serverHandshakeIV[:0]
	t.clientHandshakeKey = t.clientHandshakeKey[:0]
	t.clientHandshakeIV = t.clientHandshakeIV[:0]

	t.serverApplicationKey = t.serverApplicationKey[:0]
	t.serverApplicationIV = t.serverApplicationIV[:0]
	t.clientApplicationKey = t.clientApplicationKey[:0]
	t.clientApplicationIV = t.clientApplicationIV[:0]

	t.sessionID = t.sessionID[:0]

	t.serverRecordCount = 0
	t.clientRecordCount = 0

	t.cipher = 0
	t.serverCipher = nil
	t.clientCipher = nil

	t.Config = nil

	pool.Put(t)
}

func (t *TLState) SetConfig(config *Config) {
	t.Config = config
}

func (t *TLState) IsHandshakeDone() bool {
	return t.handshakeState == HandshakeStateDone
}

func (t *TLState) GetSelectedCipher() CipherSuite {
	return t.cipher
}

// Will read data from "inOut" buffer. If the ResponseState is "Responded", "inOut" will include data you need to send to the client
func (t *TLState) Feed(inOut *byteBuffer.ByteBuffer) (ResponseState, error) {
	t.incoming.Write(inOut.B)

	if t.handshakeState != HandshakeStateDone {
		return t.processHandshake(inOut), nil
	}

	return None, nil
}

// Will write to data to "out". Check ResponseState for "Responded" to know if anything was written to the buffer
func (t *TLState) Read(out *byteBuffer.ByteBuffer) (ResponseState, error) {
	if t.handshakeState != HandshakeStateDone {
		log.Debug().Msg("Handshake not completed, cannot read application data")
		return None, nil
	}

	return t.processApplicationData(out), nil
}

// Write application data into buff. Data in buff will be replaced with encrypted data
func (t *TLState) Write(buff *byteBuffer.ByteBuffer) error {
	if t.handshakeState != HandshakeStateDone {
		return ErrReadDuringHandshake
	}

	return t.encryptApplicationData(buff)
}

func (t *TLState) createAEAD(key []byte) (cipher.AEAD, error) {
	switch t.cipher {
	case TLS_CHACHA20_POLY1305_SHA256:
		return chacha20poly1305.New(key)
	case TLS_AES_128_GCM_SHA256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	default:
		return nil, ErrCipherNotImplemented
	}
}
