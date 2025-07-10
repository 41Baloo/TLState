package TLState

import (
	"crypto"
	"crypto/rsa"
)

/*
Precalculate options, so we avoid 1 heap alloc on interface conversion
*/

var (
	SHA256_OPTIONS crypto.SignerOpts = crypto.SHA256
	SHA384_OPTIONS crypto.SignerOpts = crypto.SHA384
	SHA512_OPTIONS crypto.SignerOpts = crypto.SHA512

	NO_OPTIONS crypto.SignerOpts = crypto.Hash(0)

	RSA_PSS_SHA256_OPTIONS = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	RSA_PSS_SHA384_OPTIONS = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA384,
	}
	RSA_PSS_SHA512_OPTIONS = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA512,
	}
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
/*
enum {
	RSASSA-PKCS1-v1_5 algorithms
	rsa_pkcs1_sha256(0x0401),
	rsa_pkcs1_sha384(0x0501),
	rsa_pkcs1_sha512(0x0601),

	ECDSA algorithms
	ecdsa_secp256r1_sha256(0x0403),
	ecdsa_secp384r1_sha384(0x0503),
	ecdsa_secp521r1_sha512(0x0603),

	RSASSA-PSS algorithms with public key OID rsaEncryption
	rsa_pss_rsae_sha256(0x0804),
	rsa_pss_rsae_sha384(0x0805),
	rsa_pss_rsae_sha512(0x0806),

	EdDSA algorithms
	ed25519(0x0807),
	ed448(0x0808),

	RSASSA-PSS algorithms with public key OID RSASSA-PSS
	rsa_pss_pss_sha256(0x0809),
	rsa_pss_pss_sha384(0x080a),
	rsa_pss_pss_sha512(0x080b),

	Legacy algorithms
	rsa_pkcs1_sha1(0x0201),
	ecdsa_sha1(0x0203),

	Reserved Code Points
	private_use(0xFE00..0xFFFF),
	(0xFFFF)
} SignatureScheme;
*/
type SignatureScheme uint16

const (
	RSA_PKCS1_SHA256 SignatureScheme = 0x0401 // PKCS1 is not allowed to be used.
	RSA_PKCS1_SHA384 SignatureScheme = 0x0501 // PKCS1 is not allowed to be used.
	RSA_PKCS1_SHA512 SignatureScheme = 0x0601 // PKCS1 is not allowed to be used.

	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureScheme = 0x0503
	ECDSA_SECP521R1_SHA512 SignatureScheme = 0x0603

	RSA_PSS_RSAE_SHA256 SignatureScheme = 0x0804
	RSA_PSS_RSAE_SHA384 SignatureScheme = 0x0805
	RSA_PSS_RSAE_SHA512 SignatureScheme = 0x0806

	ED25519 SignatureScheme = 0x0807
	ED448   SignatureScheme = 0x0808 // No golang support

	RSA_PSS_PSS_SHA256 SignatureScheme = 0x0809 // No golang support
	RSA_PSS_PSS_SHA384 SignatureScheme = 0x080a // No golang support
	RSA_PSS_PSS_SHA512 SignatureScheme = 0x080b // No golang support
)

func (s SignatureScheme) ToBytes() []byte {
	return []byte{byte(s >> 8), byte(s & 0xFF)}
}

func (s SignatureScheme) ToBytesConst() []byte {
	switch s {
	case RSA_PKCS1_SHA256:
		return []byte{0x04, 0x01}
	case RSA_PKCS1_SHA384:
		return []byte{0x05, 0x01}
	case RSA_PKCS1_SHA512:
		return []byte{0x06, 0x01}
	case ECDSA_SECP256R1_SHA256:
		return []byte{0x04, 0x03}
	case ECDSA_SECP384R1_SHA384:
		return []byte{0x05, 0x03}
	case ECDSA_SECP521R1_SHA512:
		return []byte{0x06, 0x03}
	case RSA_PSS_RSAE_SHA256:
		return []byte{0x08, 0x04}
	case RSA_PSS_RSAE_SHA384:
		return []byte{0x08, 0x05}
	case RSA_PSS_RSAE_SHA512:
		return []byte{0x08, 0x06}
	case ED25519:
		return []byte{0x08, 0x07}
	case ED448:
		return []byte{0x08, 0x08}
	case RSA_PSS_PSS_SHA256:
		return []byte{0x08, 0x09}
	case RSA_PSS_PSS_SHA384:
		return []byte{0x08, 0x0a}
	case RSA_PSS_PSS_SHA512:
		return []byte{0x08, 0x0b}
	default:
		panic("unsupported signature scheme")
	}
}

func (s SignatureScheme) GetHash() crypto.Hash {
	switch s {
	case RSA_PKCS1_SHA256, RSA_PSS_RSAE_SHA256, ECDSA_SECP256R1_SHA256, RSA_PSS_PSS_SHA256:
		return crypto.SHA256
	case RSA_PKCS1_SHA384, RSA_PSS_RSAE_SHA384, ECDSA_SECP384R1_SHA384, RSA_PSS_PSS_SHA384:
		return crypto.SHA384
	case RSA_PKCS1_SHA512, RSA_PSS_RSAE_SHA512, ECDSA_SECP521R1_SHA512, RSA_PSS_PSS_SHA512:
		return crypto.SHA512
	case ED25519:
		return 0 // Ed25519 doesn't use pre-hashing
	default:
		panic("unsupported signature scheme hash")
	}
}

func (s SignatureScheme) GetSignerOpts() crypto.SignerOpts {
	switch s {

	case RSA_PSS_RSAE_SHA256, RSA_PSS_PSS_SHA256:
		return RSA_PSS_SHA256_OPTIONS
	case RSA_PSS_RSAE_SHA384, RSA_PSS_PSS_SHA384:
		return RSA_PSS_SHA384_OPTIONS
	case RSA_PSS_RSAE_SHA512, RSA_PSS_PSS_SHA512:
		return RSA_PSS_SHA512_OPTIONS

	case RSA_PKCS1_SHA256, ECDSA_SECP256R1_SHA256:
		return SHA256_OPTIONS
	case RSA_PKCS1_SHA384, ECDSA_SECP384R1_SHA384:
		return SHA384_OPTIONS
	case RSA_PKCS1_SHA512, ECDSA_SECP521R1_SHA512:
		return SHA512_OPTIONS

	case ED25519:
		return NO_OPTIONS
	default:
		panic("unsupported signature scheme hash")
	}
}

func (s SignatureScheme) IsEdDSA() bool {
	return s == ED25519 || s == ED448
}

func (s SignatureScheme) IsECDSA() bool {
	return s == ECDSA_SECP256R1_SHA256 || s == ECDSA_SECP384R1_SHA384 || s == ECDSA_SECP521R1_SHA512
}

func (s SignatureScheme) IsRSAPSS() bool {
	return s == RSA_PSS_RSAE_SHA256 || s == RSA_PSS_RSAE_SHA384 || s == RSA_PSS_RSAE_SHA512 ||
		s == RSA_PSS_PSS_SHA256 || s == RSA_PSS_PSS_SHA384 || s == RSA_PSS_PSS_SHA512
}

func (s SignatureScheme) IsRSAPKCS1() bool {
	return s == RSA_PKCS1_SHA256 || s == RSA_PKCS1_SHA384 || s == RSA_PKCS1_SHA512
}

func (s SignatureScheme) String() string {
	switch s {
	case RSA_PKCS1_SHA256:
		return "RSA_PKCS1_SHA256"
	case RSA_PKCS1_SHA384:
		return "RSA_PKCS1_SHA384"
	case RSA_PKCS1_SHA512:
		return "RSA_PKCS1_SHA512"
	case ECDSA_SECP256R1_SHA256:
		return "ECDSA_SECP256R1_SHA256"
	case ECDSA_SECP384R1_SHA384:
		return "ECDSA_SECP384R1_SHA384"
	case ECDSA_SECP521R1_SHA512:
		return "ECDSA_SECP521R1_SHA512"
	case RSA_PSS_RSAE_SHA256:
		return "RSA_PSS_RSAE_SHA256"
	case RSA_PSS_RSAE_SHA384:
		return "RSA_PSS_RSAE_SHA384"
	case RSA_PSS_RSAE_SHA512:
		return "RSA_PSS_RSAE_SHA512"
	case ED25519:
		return "ED25519"
	case ED448:
		return "ED448"
	case RSA_PSS_PSS_SHA256:
		return "RSA_PSS_PSS_SHA256"
	case RSA_PSS_PSS_SHA384:
		return "RSA_PSS_PSS_SHA384"
	case RSA_PSS_PSS_SHA512:
		return "RSA_PSS_PSS_SHA512"
	default:
		return "Invalid SignatureScheme"
	}
}
