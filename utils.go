package TLState

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"io"
	"unsafe"
	_ "unsafe"

	"github.com/41Baloo/TLState/byteBuffer"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

func GetHeadTail(i int, head []byte, tail []byte) byte {
	if i < len(head) {
		return head[i]
	}
	return tail[i-len(head)]
}

// Should always get inlined, so no heap allocs (except append path, obviously)
func EnsureLen(b []byte, n int) []byte {
	if n <= cap(b) {
		// Backing array is big enough
		return b[:n]
	}
	// Grow via append (this *should* continue using the same backing array)
	return append(b, make([]byte, n-len(b))...)
}

// Fastest way i found to zero a slice
func ZeroSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)))
}

func UnsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func hkdfExtract(saltInOut *byteBuffer.ByteBuffer, hash *HashSettings, ikm []byte) ResponseState {
	h := hmac.New(hash.newFunc, saltInOut.B)
	saltInOut.Reset()
	h.Write(ikm)
	saltInOut.Write(h.Sum(nil))

	return Responded
}

func hkdfExpandLabel(out *byteBuffer.ByteBuffer, hash *HashSettings, secret []byte, label string, context []byte, length int) (ResponseState, error) {

	// This isnt our actual output but we can temporarily use it here to avoid a heap escape
	out.Write([]byte{
		byte(length >> 8), byte(length),
	})

	labelWithPrefix := []byte("tls13 " + label)

	out.WriteByte(byte(len(labelWithPrefix)))
	out.Write(labelWithPrefix)

	out.WriteByte(byte(len(context)))
	out.Write(context)

	expander := hkdf.Expand(hash.newFunc, secret, out.B)

	out.Reset()
	out.B = EnsureLen(out.B, length)

	_, err := io.ReadFull(expander, out.B)
	if err != nil {
		return None, err
	}

	return Responded, nil
}

func (t *TLState) createAEAD(key []byte) (cipher.AEAD, error) {
	switch t.cipher {
	case TLS_CHACHA20_POLY1305_SHA256:
		return chacha20poly1305.New(key)
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	default:
		return nil, ErrCipherNotImplemented
	}
}

func (t *TLState) setupHandshakeKeys() error {

	curve := t.namedGroup.GetCurve()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	publicKey := privateKey.PublicKey()

	t.privateKey = append(t.privateKey, privateKey.Bytes()...)
	t.publicKey = append(t.publicKey, publicKey.Bytes()...)

	return nil
}

func (t *TLState) calculateHandshakeKeys() error {

	curve := t.namedGroup.GetCurve()

	privateKey, err := curve.NewPrivateKey(t.privateKey)
	if err != nil {
		return err
	}

	pPublicKey, err := curve.NewPublicKey(t.peerPublicKey)
	if err != nil {
		return err
	}

	sharedSecret, err := privateKey.ECDH(pPublicKey)
	if err != nil {
		return err
	}

	transcriptHash, hash := t.calculateTranscriptHash()

	buff := byteBuffer.Get()
	defer byteBuffer.Put(buff)
	buff.B = EnsureLen(buff.B, hash.size)
	ZeroSlice(buff.B)

	hkdfExtract(buff, hash, buff.B)
	earlySecret := make([]byte, hash.size) // Escapes to heap
	copy(earlySecret, buff.B)

	buff.Reset()

	//derivedSecret
	_, err = hkdfExpandLabel(buff, hash, earlySecret, "derived", hash.nullValue, hash.size)
	if err != nil {
		return err
	}
	hkdfExtract(buff, hash, sharedSecret)
	t.handshakeSecret = append(t.handshakeSecret, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(
		buff,
		hash,
		t.handshakeSecret,
		"c hs traffic",
		transcriptHash,
		hash.size,
	)
	if err != nil {
		return err
	}
	t.clientHandshakeTrafficSecret = append(t.clientHandshakeTrafficSecret, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(
		buff,
		hash,
		t.handshakeSecret,
		"s hs traffic",
		transcriptHash,
		hash.size,
	)
	if err != nil {
		return err
	}
	t.serverHandshakeTrafficSecret = append(t.serverHandshakeTrafficSecret, buff.B...)
	buff.Reset()

	// Derive keys and IVs
	keyLen := t.cipher.KeyLen()
	_, err = hkdfExpandLabel(buff, hash, t.clientHandshakeTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.clientHandshakeKey = append(t.clientHandshakeKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.serverHandshakeTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.serverHandshakeKey = append(t.serverHandshakeKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.clientHandshakeTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.clientHandshakeIV = append(t.clientHandshakeIV, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.serverHandshakeTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.serverHandshakeIV = append(t.serverHandshakeIV, buff.B...)

	// Reset record counters
	t.clientRecordCount = 0
	t.serverRecordCount = 0

	return nil
}

func (t *TLState) calculateApplicationKeys() error {

	transcriptHash, hash := t.calculateTranscriptHash()

	buff := byteBuffer.Get()
	defer byteBuffer.Put(buff)

	// derivedSecret
	_, err := hkdfExpandLabel(
		buff,
		hash,
		t.handshakeSecret,
		"derived",
		hash.nullValue,
		hash.size,
	)
	if err != nil {
		return err
	}

	zeros := make([]byte, hash.size) // Escapes to heap
	hkdfExtract(buff, hash, zeros)
	masterSecret := make([]byte, buff.Len()) // Escapes to heap
	copy(masterSecret, buff.B)

	buff.Reset()

	// t.clientApplicationTrafficSecret
	_, err = hkdfExpandLabel(
		buff,
		hash,
		masterSecret,
		"c ap traffic",
		transcriptHash,
		hash.size,
	)
	if err != nil {
		return err
	}
	t.clientApplicationTrafficSecret = append(t.clientApplicationTrafficSecret, buff.B...)
	buff.Reset()

	// t.serverApplicationTrafficSecret
	_, err = hkdfExpandLabel(
		buff,
		hash,
		masterSecret,
		"s ap traffic",
		transcriptHash,
		hash.size,
	)
	if err != nil {
		return err
	}
	t.serverApplicationTrafficSecret = append(t.serverApplicationTrafficSecret, buff.B...)
	buff.Reset()

	keyLen := t.cipher.KeyLen()
	_, err = hkdfExpandLabel(buff, hash, t.clientApplicationTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.clientApplicationKey = append(t.clientApplicationKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.serverApplicationTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.serverApplicationKey = append(t.serverApplicationKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.clientApplicationTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.clientApplicationIV = append(t.clientApplicationIV, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, hash, t.serverApplicationTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.serverApplicationIV = append(t.serverApplicationIV, buff.B...)
	buff.Reset()

	t.clientRecordCount = 0
	t.serverRecordCount = 0

	t.handshakeState = HandshakeStateDone

	return nil
}

func (t *TLState) calculateVerifyData(out *byteBuffer.ByteBuffer, secret []byte) (ResponseState, error) {
	transcriptHash, hash := t.calculateTranscriptHash() // Moved to heap

	resp, err := hkdfExpandLabel(out, hash, secret, "finished", []byte{}, hash.size)
	if err != nil {
		return resp, err
	}

	outLength := out.Len()

	out.Write(transcriptHash)

	h := hmac.New(hash.newFunc, out.B[:outLength])
	h.Write(out.B[outLength:])

	out.Reset()
	out.Write(h.Sum(nil))

	return Responded, nil
}

// Also returns hashSettings to save a few switch statements
func (t *TLState) calculateTranscriptHash() (result []byte, hash *HashSettings) {
	h := t.cipher.GetHash()
	return h.Hash(t.handshakeMessages.B), h
}
