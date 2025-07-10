package TLState

import "crypto/ecdh"

var (
	CURVE_P256   ecdh.Curve = ecdh.P256()
	CURVE_X25519 ecdh.Curve = ecdh.X25519()
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
/*
	enum {
		Elliptic Curve Groups (ECDHE)
		secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
		x25519(0x001D), x448(0x001E),

		Finite Field Groups (DHE)
		ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
		ffdhe6144(0x0103), ffdhe8192(0x0104),

		Reserved Code Points
		ffdhe_private_use(0x01FC..0x01FF),
		ecdhe_private_use(0xFE00..0xFEFF),
		(0xFFFF)
	} NamedGroup;
*/
type NamedGroup uint16

const (
	NamedGroupP256   NamedGroup = 0x0017 // aka secp256r1 or prime256v1
	NamedGroupX25519 NamedGroup = 0x001D
)

func (n NamedGroup) ToBytes() []byte {
	return []byte{byte(n >> 8), byte(n & 0xFF)}
}

func (n NamedGroup) ToBytesConst() []byte {
	switch n {
	case NamedGroupP256:
		return []byte{0x00, 0x17}
	case NamedGroupX25519:
		return []byte{0x00, 0x1D}
	default:
		panic("unsupported named group")
	}
}

func (n NamedGroup) GetCurve() ecdh.Curve {
	switch n {
	case NamedGroupP256:
		return CURVE_P256
	case NamedGroupX25519:
		return CURVE_X25519
	default:
		panic("unsupported named group")
	}
}

func (n NamedGroup) String() string {
	switch n {
	case NamedGroupP256:
		return "P-256"
	case NamedGroupX25519:
		return "X25519"
	default:
		return "Invalid NamedGroup"
	}
}
