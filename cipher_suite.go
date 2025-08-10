package TLState

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	_sha256NullTmp = sha256.Sum256(nil)
	_sha384NullTmp = sha512.Sum384(nil)

	HASH_SHA256_SETTINGS = &HashSettings{
		nullValue: _sha256NullTmp[:],
		size:      sha256.Size,
		newFunc:   sha256.New,
		hash:      SHA256,
	}

	HASH_SHA384_SETTINGS = &HashSettings{
		nullValue: _sha384NullTmp[:],
		size:      sha512.Size384,
		newFunc:   sha512.New384,
		hash:      SHA384,
	}
)

type cipherHash uint8

const (
	SHA256 cipherHash = iota
	SHA384
)

type HashSettings struct {
	nullValue []byte // stores hash(nil)
	size      int
	newFunc   func() hash.Hash
	hash      cipherHash
}

func (h HashSettings) Hash(data []byte) []byte {
	switch h.hash {
	case SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	default:
		panic("unknown hash")
	}
}

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
/*
+------------------------------+-------------+
| Description                  | Value       |
+------------------------------+-------------+
| TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
|                              |             |
| TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
|                              |             |
| TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
|                              |             |
| TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
|                              |             |
| TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
+------------------------------+-------------+
*/
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256 CipherSuite = (0x1301 + iota)
	TLS_AES_256_GCM_SHA384
	TLS_CHACHA20_POLY1305_SHA256

	/*
		NOT IMPLEMENTED.

		See https://github.com/golang/go/issues/27484
	*/
	TLS_AES_128_CCM_SHA256   // CCM not implemented
	TLS_AES_128_CCM_8_SHA256 // CCM not implemented
)

func GetCipherSuiteOrderedSecure() []CipherSuite {
	return []CipherSuite{
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_GCM_SHA256,
	}
}

func GetCipherSuiteOrderedPerformance() []CipherSuite {
	return []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_256_GCM_SHA384,
	}
}

func GetCipherSuiteDefault() []CipherSuite {
	return GetCipherSuiteOrderedPerformance()
}

func (c CipherSuite) GetHash() *HashSettings {
	switch c {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		return HASH_SHA256_SETTINGS
	case TLS_AES_256_GCM_SHA384:
		return HASH_SHA384_SETTINGS
	default:
		panic("unsupported cipher suite " + c.String())
	}
}

func (c CipherSuite) KeyLen() int {
	switch c {
	case TLS_AES_128_GCM_SHA256:
		return 16
	case TLS_AES_256_GCM_SHA384:
		return 32
	case TLS_CHACHA20_POLY1305_SHA256:
		return chacha20poly1305.KeySize
	default:
		panic("unsupported cipher suite for key length")
	}
}

func (c CipherSuite) ToBytes() []byte {
	return []byte{byte(c >> 8), byte(c & 0xFF)}
}

func (c CipherSuite) String() string {
	switch c {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_128_CCM_8_SHA256:
		return "TLS_AES_128_CCM_8_SHA256"
	default:
		return "Invalid CipherSuite"
	}
}
