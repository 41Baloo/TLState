package TLState

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/41Baloo/TLState/byteBuffer"
	ringBuffer "github.com/panjf2000/gnet/v2/pkg/pool/ringbuffer"
	"github.com/rs/zerolog/log"
)

var (
	ErrConfigNotInitialized = errors.New("the given config is not intialized yet")
	ErrStateClosed          = errors.New("attempted to use closed state")

	ErrReadDuringHandshake         = errors.New("cannot read application data before completing handshake")
	ErrCipherNotImplemented        = errors.New("the selected cipher in Config is not implemented yet")
	ErrClientFinishVerifyMissmatch = errors.New("client finished verify data and our verify data mismatch")

	ErrUnexpectedMessage = errors.New("unexpected message")

	ErrInvalidX25519MLKEM768Keyshare = errors.New("invalid X25519MLKEM768 key share")
	ErrInvalidSessionId              = errors.New("invalid sessionId")
	ErrInvalidKeyshareLength         = errors.New("invalid key share length")

	ErrTLS13NotSupported       = errors.New("client does not support TLS 1.3")           // The clientHello did not suggest the client supports TLS 1.3. As a special case, as long as the ResponseStatus is "Responded", you may still flush the buffer to the client, to alert them
	ErrNamedGroupsNotSupported = errors.New("client does not support our given curves")  // The clientHello did not include a valid keyshare. You may still flush the buffer to the client, to alert them, if ResponseStatus is "Responded"
	ErrCiphersNotSupported     = errors.New("client does not support our given ciphers") // The clientHello did not suggest that the client supports TLS 1.3. You may still flush the buffer to the client, to alert them, if ResponseStatus is "Responded"
	ErrSchemesNotSupported     = errors.New("client does not support our signature(s)")  // The clientHello did not suggest that the client supports our signature(s). You may still flush the buffer to the client, to alert them, if ResponseStatus is "Responded"

	ErrUnknownRecordType              = errors.New("unknown record type")
	ErrApplicationDataDuringHandshake = errors.New("application data received during handshake")
	ErrMalformedAlert                 = errors.New("client sent a malformed alert")
	ErrFatalAlert                     = errors.New("client has sent a fatal alert")
)

type HandshakeState uint8

const (
	HandshakeStateInitial              HandshakeState = iota
	HandshakeStateProcessedClientHello                // parsed ClientHello
	HandshakeStateSentServerFlight                    // sent ServerHello
	HandshakeStateWaitClientFinished                  // waiting for client
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
	config *Config

	incoming          *ringBuffer.RingBuffer
	handshakeMessages *byteBuffer.ByteBuffer

	privateKey    []byte
	publicKey     []byte
	peerPublicKey []byte
	mlkemSecret   []byte // Only used for X25519MLKEM768

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

	tls13      bool
	namedGroup NamedGroup
	cipher     CipherSuite
	scheme     SignatureScheme

	handshakeCipher cipher.AEAD
	clientCipher    cipher.AEAD
	serverCipher    cipher.AEAD

	clientRandom []byte
	sessionID    []byte

	sniIndex uint32
	closed   bool // If the connection is considered closed, we can no longer do anything.
}

var pool = &sync.Pool{
	New: func() interface{} {
		return &TLState{
			incoming:          ringBuffer.Get(),
			handshakeMessages: byteBuffer.Get(),

			privateKey:    make([]byte, 0, 32),
			publicKey:     make([]byte, 0, 1120),
			peerPublicKey: make([]byte, 0, 1216),
			mlkemSecret:   make([]byte, 0, 32),

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

	return state, nil
}

func Put(t *TLState) {

	t.incoming.Reset()
	t.handshakeMessages.Reset()

	t.privateKey = t.privateKey[:0]
	t.publicKey = t.publicKey[:0]
	t.handshakeState = HandshakeStateInitial

	t.peerPublicKey = t.peerPublicKey[:0]
	t.mlkemSecret = t.mlkemSecret[:0]

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

	t.tls13 = false
	t.namedGroup = 0
	t.cipher = 0
	t.scheme = 0

	t.serverCipher = nil
	t.clientCipher = nil
	t.handshakeCipher = nil

	t.config = nil
	t.closed = false

	pool.Put(t)
}

func (t *TLState) SetConfig(config *Config) error {
	if config == nil || !config.initialised {
		return ErrConfigNotInitialized
	}

	t.config = config

	return nil
}

func (t *TLState) IsHandshakeDone() bool {
	return t.handshakeState == HandshakeStateDone
}

func (t *TLState) GetSelectedNamedGroup() NamedGroup {
	return t.namedGroup
}

func (t *TLState) GetSelectedCipher() CipherSuite {
	return t.cipher
}

func (t *TLState) GetSignatureScheme() SignatureScheme {
	return t.scheme
}

func (t *TLState) GetSessionID() []byte {
	return t.sessionID
}

func (t *TLState) GetClientRandom() []byte {
	return t.clientRandom
}

func (t *TLState) GetClientRecordCount() uint64 {
	return t.clientRecordCount
}

func (t *TLState) GetServerRecordCount() uint64 {
	return t.serverRecordCount
}

func (t *TLState) IsClosed() bool {
	return t.closed
}

// Will read data from "inOut" buffer. If the ResponseState is "Responded", "inOut" will include data you need to send to the client
func (t *TLState) Feed(inOut *byteBuffer.ByteBuffer) (ResponseState, error) {

	if t.closed {
		return None, ErrStateClosed
	}

	t.incoming.Write(inOut.B)

	if t.handshakeState != HandshakeStateDone {
		return t.processHandshake(inOut)
	}

	return None, nil
}

// Will append data to "out". Check ResponseState for "Responded" to know if anything was written to the buffer
func (t *TLState) Read(out *byteBuffer.ByteBuffer) (ResponseState, error) {
	if t.handshakeState != HandshakeStateDone {
		log.Debug().Msg("Handshake not completed, cannot read application data")
		return None, nil
	}

	return t.processApplicationData(out)
}

// Write application data into buff. Data in buff will be replaced with encrypted data
func (t *TLState) Write(buff *byteBuffer.ByteBuffer) error {

	if t.closed {
		return ErrStateClosed
	}

	if t.handshakeState != HandshakeStateDone {
		return ErrReadDuringHandshake
	}

	buffLen := buff.Len()

	// Fast path, buffer smaller than 2^14
	if buffLen <= MaxTLSRecordSize {
		return t.encryptApplicationData(buff)
	}

	input := make([]byte, buffLen)
	copy(input, buff.B[MaxTLSRecordSize:])
	buff.B = buff.B[:MaxTLSRecordSize]

	inBuff := byteBuffer.Get()
	defer byteBuffer.Put(inBuff)

	for off := -MaxTLSRecordSize; off < buffLen; off += MaxTLSRecordSize {
		end := off + MaxTLSRecordSize
		if end > buffLen {
			end = buffLen
		}

		// For the first iteration we can still use the original buffer
		// this saves us 2 write operations and 2^14 bytes in copy
		if off == -MaxTLSRecordSize {
			err := t.encryptApplicationData(buff)
			if err != nil {
				return err
			}
		} else {
			inBuff.Write(input[off:end])
			err := t.encryptApplicationData(inBuff)
			if err != nil {
				return err
			}
			buff.Write(inBuff.B)
			inBuff.Reset()
		}
	}

	return nil
}

func (t *TLState) processApplicationData(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	for {

		buffered := t.incoming.Buffered()
		if buffered < 5 {
			return None, nil
		}

		head, tail := t.incoming.Peek(5)
		recType := RecordType(head[0])

		b0 := GetHeadTail(2, head[1:], tail)
		b1 := GetHeadTail(3, head[1:], tail)

		length := int(binary.BigEndian.Uint16([]byte{b0, b1}))

		if buffered < 5+length {
			return None, nil
		}

		headerHead, headerTail := t.incoming.Peek(5)
		t.incoming.Discard(5)

		head, tail = t.incoming.Peek(length)
		t.incoming.Discard(length)

		// Instead of just writing the result into the buffer we can temporarily use it to get rid of 1 heap allocated slice
		// We write recordData into the out buffer temporarily

		// Preserve current length so we can skip back to it
		outLength := out.Len()

		out.Write(head)
		out.Write(tail)

		// This is getting really fucking hacky. Since we know the header is of length 5 and the clientIV is of length 12, we can
		// just write to out and use windows to the backing slice instead, to avoid 2 heap allocs
		cipherLength := out.Len()
		cipherText := out.B[outLength:cipherLength]

		out.Write(headerHead)
		out.Write(headerTail)
		additionalData := out.B[cipherLength:]

		if recType != RecordTypeApplicationData {
			log.Debug().Uint8("record_type", uint8(recType)).Msg("Skipping non-application-data record")
			out.B = out.B[:outLength]
			continue
		}

		out.Write(t.clientApplicationIV)
		nonce := out.B[cipherLength+5:]

		seq := make([]byte, 8)
		binary.BigEndian.PutUint64(seq, t.clientRecordCount)
		for i := 0; i < 8; i++ {
			nonce[4+i] ^= seq[i]
		}
		t.clientRecordCount++

		if t.clientCipher == nil {
			aead, err := t.createAEAD(t.clientApplicationKey)
			if err != nil {
				out.B = out.B[:outLength]
				return None, err
			}
			t.clientCipher = aead
		}

		// See tls13.go:encryptApplicationData to understand this hack better
		fLength := out.Len()
		out.B = EnsureLen(out.B, fLength+cipherLength+t.clientCipher.Overhead())

		plaintext, err := t.clientCipher.Open(
			out.B[fLength:fLength],
			nonce,
			cipherText,
			additionalData,
		)
		if err != nil {
			out.B = out.B[:outLength]
			return None, err
		}

		if len(plaintext) == 0 {
			log.Warn().Msg("Empty plaintext after decryption")
			out.B = out.B[:outLength]
			continue
		}
		contentType := RecordType(plaintext[len(plaintext)-1])
		plaintext = plaintext[:len(plaintext)-1]

		// Fullfilled its temporary use, now write the output by first resetting to original length and then appening
		out.B = out.B[:outLength]

		switch contentType {
		case RecordTypeApplicationData:
			out.Write(plaintext)
			return Responded, nil
		case RecordTypeAlert:
			err = t.handleAlert(plaintext)
			if err != nil {
				return None, err
			}
		default:
			log.Debug().Uint8("content_type", uint8(contentType)).Msg("Skipping non-application content type")
		}
	}
}

func (t *TLState) encryptApplicationData(buff *byteBuffer.ByteBuffer) error {
	return t.encryptRecord(buff, RecordTypeApplicationData)
}

// Data in buff will be whiped. Read encrypted data from buff after function call
// buff.B may not be longer than 2^14
func (t *TLState) encryptRecord(buff *byteBuffer.ByteBuffer, rType RecordType) error {

	isApplicationPhase := t.handshakeState == HandshakeStateDone

	var tCipher *cipher.AEAD
	var key []byte
	var iv []byte

	if isApplicationPhase {
		tCipher = &t.serverCipher
		key = t.serverApplicationKey
		iv = t.serverApplicationIV
	} else {
		tCipher = &t.handshakeCipher
		key = t.serverHandshakeKey
		iv = t.serverHandshakeIV
	}

	buff.WriteByte(byte(rType))

	dataLength := buff.Len()

	recordLength := dataLength + 16 // Add 16 for auth tag

	buff.Write(iv)
	nonce := buff.B[dataLength:]

	buff.Write(marshallAdditionalData(recordLength))
	additionalData := buff.B[dataLength+12:]

	// XOR the last bytes with the record count
	nonceCount := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceCount, t.serverRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.serverRecordCount++

	if *tCipher == nil {
		aead, err := t.createAEAD(key)
		if err != nil {
			return err
		}

		*tCipher = aead
	}

	// This is our final input length. .Seal will write the ciphertext into the remaining space of our buffer and if needed, expand it.
	// This saves us having to use a second buffer and should also fully eliminate heap allocations caused by .Seal
	fLength := buff.Len()
	// We want at least current length + data length + overhead, so .Seal never has to allocate
	buff.B = EnsureLen(buff.B, fLength+dataLength+(*tCipher).Overhead())

	ciphertext := (*tCipher).Seal(
		buff.B[fLength:fLength],
		nonce,
		buff.B[:dataLength],
		additionalData,
	)

	// At this point we have read everything we needed into our stack.
	// We re-use our input buffer to return needed data.
	// Ideally this would mean nothing gets pushed to heap, however calling aead.Seal
	// automatically pushes everything to heap since it's an interface
	buff.Reset()

	// Sadly if we were to cut the plaintext from the start, we would loose len(plaintext) capacity from our buffer
	// benchmarking makes it appear as if this is not a worthy traitoff, so we instead write additionalData to the buffer twice.
	buff.Write(additionalData)
	buff.Write(ciphertext)

	return nil
}
