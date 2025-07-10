package TLState

import (
	"encoding/binary"

	"github.com/41Baloo/TLState/byteBuffer"
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
	RecordTypeInvalid      RecordType = 0
	RecordTypeChangeCipher RecordType = (0x13 + iota)
	RecordTypeAlert
	RecordTypeHandshake
	RecordTypeApplicationData
	RecordTypeHeartbeat
)

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
