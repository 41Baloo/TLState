package TLState

import (
	"io"

	"github.com/41Baloo/TLState/byteBuffer"
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

type AlertCallback func(level AlertLevel, description AlertDescription)

func (t *TLState) handleAlert(in []byte) error {
	if len(in) < 2 {
		return ErrMalformedAlert
	}

	level := AlertLevel(in[0])
	description := AlertDescription(in[1])

	if t.config.alertCallback != nil {
		t.config.alertCallback(level, description)
	}

	// As a special case, we return EOF here to let users know the connection should never be read from again
	// "This alert notifies the recipient that the sender will not send any more messages on this connection.
	// Any data received after a closure alert has been received MUST be ignored" ~ https://datatracker.ietf.org/doc/html/rfc8446#section-6.1
	if description == AlertDescriptionCloseNotify {
		t.closed = true
		return io.EOF
	}

	// https://datatracker.ietf.org/doc/html/rfc8446#section-6.2
	// "Upon transmission or receipt of a fatal alert message, both parties MUST immediately close the connection"
	if level == AlertLevelFatal {
		t.closed = true
		return ErrFatalAlert
	}

	return nil
}

func (t *TLState) BuildAlert(level AlertLevel, desc AlertDescription, out *byteBuffer.ByteBuffer) error {

	if level == AlertLevelFatal {
		t.closed = true
	}

	out.WriteByte(byte(level))
	out.WriteByte(byte(desc))

	if t.handshakeState < HandshakeStateSentServerFlight {
		BuildRecordMessage(RecordTypeAlert, out)
		return nil
	}

	return t.encryptRecord(out, RecordTypeAlert)
}
