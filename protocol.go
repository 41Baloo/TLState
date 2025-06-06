package TLState

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"io"

	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
	/*
		The record layer fragments information blocks into TLSPlaintext
		records carrying data in chunks of 2^14 bytes or less.
	*/
	MaxTLSRecordSize = 1 << 14
)

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1
/*
enum {
	invalid(0),
	change_cipher_spec(20),
	alert(21),
	handshake(22),
	application_data(23),
	heartbeat(24),  RFC 6520
	(255)
} ContentType;
*/
type RecordType uint8

const (
	RecordTypeInvalid      RecordType = iota
	RecordTypeChangeCipher RecordType = (0x13 + iota)
	RecordTypeAlert
	RecordTypeHandshake
	RecordTypeApplicationData
	RecordTypeHeartbeat
)

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3
/*
enum {
	hello_request_RESERVED(0),
	client_hello(1),
	server_hello(2),
	hello_verify_request_RESERVED(3),
	new_session_ticket(4),
	end_of_early_data(5),
	hello_retry_request_RESERVED(6),
	encrypted_extensions(8),
	certificate(11),
	server_key_exchange_RESERVED(12),
	certificate_request(13),
	server_hello_done_RESERVED(14),
	certificate_verify(15),
	client_key_exchange_RESERVED(16),
	finished(20),
	certificate_url_RESERVED(21),
	certificate_status_RESERVED(22),
	supplemental_data_RESERVED(23),
	key_update(24),
	message_hash(254),
	(255)
} HandshakeType;
*/
type HandshakeType uint8

const (
	HandshakeTypeRequest_RESERVED HandshakeType = iota
	HandshakeTypeClientHello
	HandshakeTypeServerHello
	HandshakeTypeVerifyRequest_RESERVED
	HandshakeTypeNewSessionTicket
	HandshakeTypeEndOfEarlyData
	HandshakeTypeRetryRequest_RESERVED
	HandshakeTypeEncryptedExtensions        HandshakeType = 8
	HandshakeTypeCertificate                HandshakeType = 11
	HandshakeTypeServerKeyExchange_RESERVED HandshakeType = iota + 3 // 12
	HandshakeTypeCertificateRequest
	HandshakeTypeServerHelloDone_RESERVED
	HandshakeTypeCertificateVerify
	HandshakeTypeClientKeyExchange_RESERVED
	HandshakeTypeFinished                HandshakeType = 20
	HandshakeTypeCertificateUrl_RESERVED HandshakeType = iota + 6 // 21
	HandshakeTypeCertificateStatus_RESERVED
	HandshakeTypeSupplementalData_RESERVED
	HandshakeTypeKeyUpdate
	HandshakeTypeMessageHash = 254
)

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
	TLS_AES_256_GCM_SHA384             // not implemented
	TLS_CHACHA20_POLY1305_SHA256
	TLS_AES_128_CCM_SHA256   // not implemented
	TLS_AES_128_CCM_8_SHA256 // not implemented
)

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
		return "UNKNOWN"
	}
}

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

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
/*
enum {
	server_name(0),                             RFC 6066
	max_fragment_length(1),                     RFC 6066
	status_request(5),                          RFC 6066
	supported_groups(10),                       RFC 8422, 7919
	signature_algorithms(13),                   RFC 8446
	use_srtp(14),                               RFC 5764
	heartbeat(15),                              RFC 6520
	application_layer_protocol_negotiation(16), RFC 7301
	signed_certificate_timestamp(18),           RFC 6962
	client_certificate_type(19),                RFC 7250
	server_certificate_type(20),                RFC 7250
	padding(21),                                RFC 7685
	pre_shared_key(41),                         RFC 8446
	early_data(42),                             RFC 8446
	supported_versions(43),                     RFC 8446
	cookie(44),                                 RFC 8446
	psk_key_exchange_modes(45),                 RFC 8446
	certificate_authorities(47),                RFC 8446
	oid_filters(48),                            RFC 8446
	post_handshake_auth(49),                    RFC 8446
	signature_algorithms_cert(50),              RFC 8446
	key_share(51),                              RFC 8446
	(65535)
} ExtensionType;
*/
type Extension uint8

const (
	ExtensionSignatureAlgorithms Extension = 13
	ExtensionSupportedVersions   Extension = 43
	ExtensionKeyShare            Extension = 51
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
	NamedGroupX25519 NamedGroup = 0x001D
)

const (
	ProtocolVersion = 0x0303 // Backwards compatibility
	TLS13Version    = 0x0304
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-6
/*
enum { warning(1), fatal(2), (255) } AlertLevel;
*/
type AlertLevel uint8

const (
	AlertLevelWarning AlertLevel = iota + 1
	AlertLevelFatal
)

func (a AlertLevel) String() string {
	switch a {
	case AlertLevelWarning:
		return "Warning"
	case AlertLevelFatal:
		return "Fatal"
	default:
		return "Invalid Level"
	}
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-6
/*
enum {
	close_notify(0),
	unexpected_message(10),
	bad_record_mac(20),
	record_overflow(22),
	handshake_failure(40),
	bad_certificate(42),
	unsupported_certificate(43),
	certificate_revoked(44),
	certificate_expired(45),
	certificate_unknown(46),
	illegal_parameter(47),
	unknown_ca(48),
	access_denied(49),
	decode_error(50),
	decrypt_error(51),
	protocol_version(70),
	insufficient_security(71),
	internal_error(80),
	inappropriate_fallback(86),
	user_canceled(90),
	missing_extension(109),
	unsupported_extension(110),
	unrecognized_name(112),
	bad_certificate_status_response(113),
	unknown_psk_identity(115),
	certificate_required(116),
	no_application_protocol(120),
	(255)
} AlertDescription;
*/
type AlertDescription uint8

const (
	AlertDescriptionCloseNotify       AlertDescription = 0
	AlertDescriptionUnexpectedMessage AlertDescription = 10
	AlertDescriptionBadRecordMac      AlertDescription = 20
	AlertDescriptionRecordOverflow    AlertDescription = 22
	AlertDescriptionHandshakeFailure  AlertDescription = 40
	AlertDescriptionBadCertificate    AlertDescription = 37 + iota
	AlertDescriptionUnsupportedCertificate
	AlertDescriptionCertificateRevoked
	AlertDescriptionCertificateExpired
	AlertDescriptionCertificateUnknown
	AlertDescriptionIllegalParameter
	AlertDescriptionUnknownCa
	AlertDescriptionAccessDenied
	AlertDescriptionDecodeError
	AlertDescriptionDecryptError
	AlertDescriptionProtocolVersion              AlertDescription = 70
	AlertDescriptionInsufficientSecurity         AlertDescription = 71
	AlertDescriptionInternalError                AlertDescription = 80
	AlertDescriptionInappropriateFallback        AlertDescription = 86
	AlertDescriptionUserCanceled                 AlertDescription = 90
	AlertDescriptionMissingExtension             AlertDescription = 109
	AlertDescriptionUnsupportedExtension         AlertDescription = 110
	AlertDescriptionUnrecognizedName             AlertDescription = 112
	AlertDescriptionBadCertificateStatusResponse AlertDescription = 113
	AlertDescriptionUnknownPskIdentity           AlertDescription = 115
	AlertDescriptionCertificateRequired          AlertDescription = 116
	AlertDescriptionNoApplicationProtocol        AlertDescription = 120
) // Srsly, whats with all of these gabs

func (a AlertDescription) String() string {
	switch a {
	case AlertDescriptionCloseNotify:
		return "close_notify"
	case AlertDescriptionUnexpectedMessage:
		return "unexpected_message"
	case AlertDescriptionBadRecordMac:
		return "bad_record_mac"
	case AlertDescriptionRecordOverflow:
		return "record_overflow"
	case AlertDescriptionHandshakeFailure:
		return "handshake_failure"
	case AlertDescriptionBadCertificate:
		return "bad_certificate"
	case AlertDescriptionUnsupportedCertificate:
		return "unsupported_certificate"
	case AlertDescriptionCertificateRevoked:
		return "certificate_revoked"
	case AlertDescriptionCertificateExpired:
		return "certificate_expired"
	case AlertDescriptionCertificateUnknown:
		return "certificate_unknown"
	case AlertDescriptionIllegalParameter:
		return "illegal_parameter"
	case AlertDescriptionUnknownCa:
		return "unknown_ca"
	case AlertDescriptionAccessDenied:
		return "access_denied"
	case AlertDescriptionDecodeError:
		return "decode_error"
	case AlertDescriptionDecryptError:
		return "decrypt_error"
	case AlertDescriptionProtocolVersion:
		return "protocol_version"
	case AlertDescriptionInsufficientSecurity:
		return "insufficient_security"
	case AlertDescriptionInternalError:
		return "internal_error"
	case AlertDescriptionInappropriateFallback:
		return "inappropriate_fallback"
	case AlertDescriptionUserCanceled:
		return "user_canceled"
	case AlertDescriptionMissingExtension:
		return "missing_extension"
	case AlertDescriptionUnsupportedExtension:
		return "unsupported_extension"
	case AlertDescriptionUnrecognizedName:
		return "unrecognized_name"
	case AlertDescriptionBadCertificateStatusResponse:
		return "bad_certificate_status_response"
	case AlertDescriptionUnknownPskIdentity:
		return "unknown_psk_identity"
	case AlertDescriptionCertificateRequired:
		return "certificate_required"
	case AlertDescriptionNoApplicationProtocol:
		return "no_application_protocol"
	default:
		return "Invalid Description"
	}
}

func handleAlert(in []byte) error {
	if len(in) < 2 {
		return ErrMalformedAlert
	}

	level := AlertLevel(in[0])
	description := AlertDescription(in[1])

	// As a special case, we return EOF here to let users know the connection should never be read from again
	// "This alert notifies the recipient that the sender will not send any more messages on this connection.
	// Any data received after a closure alert has been received MUST be ignored" ~ https://datatracker.ietf.org/doc/html/rfc8446#section-6.1
	if description == AlertDescriptionCloseNotify {
		return io.EOF
	}

	log.Warn().
		Str("Level", level.String()).
		Str("Description", description.String()).
		Msg("Alert received")

	// https://datatracker.ietf.org/doc/html/rfc8446#section-6.2
	// "Upon transmission or receipt of a fatal alert message, both parties MUST immediately close the connection"
	if level == AlertLevelFatal {
		return ErrFatalAlert
	}

	return nil
}

func marshallAlert(level AlertLevel, desc AlertDescription, out *byteBuffer.ByteBuffer) ResponseState {
	out.WriteByte(byte(level))
	out.WriteByte(byte(desc))
	return BuildRecordMessage(RecordTypeAlert, out)
}

// will use the contents of "inOut" buffer and replace them with a handshakeMessage
func marshallHandshake(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) ResponseState {

	bodyLen := inOut.Len()

	// Shift back inOut by 4 bytes, to prepend headers directly. This avoids 1 heap allocation
	// but comes at the cost of O(n) copying the pre-existing buffer. However append would
	// come at the same cost, so this should be more efficient.
	inOut.B = EnsureLen(inOut.B, bodyLen+4)
	copy(inOut.B[4:], inOut.B[:bodyLen])

	inOut.B[0] = byte(msgType)
	inOut.B[1] = byte(bodyLen >> 16)
	inOut.B[2] = byte(bodyLen >> 8)
	inOut.B[3] = byte(bodyLen)

	return Responded
}

func marshallAdditionalData(length int) []byte {
	return []byte{ // Escapes to heap
		byte(RecordTypeApplicationData),
		byte(ProtocolVersion >> 8),
		byte(ProtocolVersion & 0xFF),
		byte(length >> 8),
		byte(length & 0xFF),
	}
}

func BuildHandshakeMessage(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) ResponseState {
	marshallHandshake(msgType, inOut)

	return BuildRecordMessage(RecordTypeHandshake, inOut)
}

// Wrap payload in full TLS record (type + version + 2-byte length).
func BuildRecordMessage(recType RecordType, inOut *byteBuffer.ByteBuffer) ResponseState {

	bodyLen := inOut.Len()

	// Same trick as with marshallHandshake
	inOut.B = EnsureLen(inOut.B, bodyLen+5)
	copy(inOut.B[5:], inOut.B[:bodyLen])

	inOut.B[0] = byte(recType)
	inOut.B[1] = byte(ProtocolVersion >> 8)
	inOut.B[2] = byte(ProtocolVersion & 0xFF)
	binary.BigEndian.PutUint16(inOut.B[3:], uint16(bodyLen))

	return Responded
}

func (t *TLState) BuildEncryptedHandshakeMessage(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) (ResponseState, error) {

	marshallHandshake(msgType, inOut)

	// record for transcript hash (per RFC8446 §4.1.3)
	t.handshakeMessages.Write(inOut.B)

	inOut.WriteByte(byte(RecordTypeHandshake))

	// Create additional data (record header)
	messageLength := inOut.Len()
	recordLength := messageLength + 16 // Add 16 for auth tag

	inOut.Write(t.serverHandshakeIV)
	nonce := inOut.B[messageLength:]

	inOut.Write(marshallAdditionalData(recordLength))
	additionalData := inOut.B[messageLength+12:]

	nonceCount := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceCount, t.serverRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.serverRecordCount++

	if t.handshakeCipher == nil {
		aead, err := t.createAEAD(t.serverHandshakeKey)
		if err != nil {
			return None, err
		}

		t.handshakeCipher = aead
	}

	// See tls13.go:encryptApplicationData to understand this hack better
	fLength := inOut.Len()
	inOut.B = EnsureLen(inOut.B, fLength+messageLength+t.handshakeCipher.Overhead())

	ciphertext := t.handshakeCipher.Seal(inOut.B[fLength:fLength], nonce, inOut.B[:messageLength], additionalData)

	// No longer need the input, time to replace it with the output.
	inOut.Reset()
	inOut.Write(additionalData)
	inOut.Write(ciphertext)

	return Responded, nil
}
