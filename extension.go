package TLState

import (
	"github.com/41Baloo/TLState/byteBuffer"
)

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
	ExtensionServerName          Extension = 0
	ExtensionSignatureAlgorithms Extension = 13
	ExtensionSupportedVersions   Extension = 43
	ExtensionKeyShare            Extension = 51
)

// Will write ServerHelloExtensions to out
func (t *TLState) generateServerHelloExtensions(out *byteBuffer.ByteBuffer) ResponseState {

	// To avoid an extra buffer here, we can instantly figure out what the final length will be
	// We instantly write it and then append the actual extenions.
	// supported_versions => 6
	// key_share => 8
	// t.publicKey => len(t.publicKey)
	pubKeyLen := len(t.publicKey)
	var EXTENSION_LENGTH = 6 + 8 + pubKeyLen
	out.Write([]byte{
		byte(EXTENSION_LENGTH >> 8), byte(EXTENSION_LENGTH),
	})

	// supported_versions extension
	out.Write([]byte{
		0x00, 0x2B, // supported_versions, not using constant here for performance
		0x00, 0x02, // Length
		0x03, 0x04, // TLS 1.3
	})

	// key_share extension
	keyShareLen := 2 + 2 + pubKeyLen
	out.Write([]byte{
		0x00, 0x33, // Extension type, not using constant, due to performance
		byte(keyShareLen >> 8), byte(keyShareLen), // Length
	})

	out.Write(t.namedGroup.ToBytesConst())

	out.Write([]byte{
		byte(pubKeyLen >> 8),
		byte(pubKeyLen),
	})

	out.Write(t.publicKey)

	return Responded
}
