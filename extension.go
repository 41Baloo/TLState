package TLState

import (
	"encoding/binary"

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

func (t *TLState) handleExtension(extension Extension, data []byte) {
	switch extension {
	case ExtensionServerName:
		t.handleServerName(data)
	case ExtensionSignatureAlgorithms:
		t.handleSignatureAlgorithms(data)
	case ExtensionSupportedVersions:
		t.handleSupportedVersions(data)
	case ExtensionKeyShare:
		t.handleKeyShare(data)
	}
}

func (t *TLState) handleServerName(data []byte) {

	dataLen := len(data)

	if dataLen < 2 || !t.config.sni {
		return
	}

	snLen := int(binary.BigEndian.Uint16(data[0:2]))

	pos := 2
	for pos+3 < 2+snLen && pos+3 <= dataLen {
		nameType := data[pos]

		pos++
		nameLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if nameType == 0 && pos+nameLen <= dataLen {
			// if the given name does not match any of our existing certificates, we fall back to 0 (our first certificate)
			t.sniIndex = t.config.GetSNICertificateIndexByName(UnsafeString(data[pos : pos+nameLen]))
		}
		pos += nameLen
	}

}

func (t *TLState) handleSignatureAlgorithms(data []byte) {

	dataLen := len(data)

	if dataLen < 2 {
		return
	}

	sigAlgsLen := int(binary.BigEndian.Uint16(data[0:2]))

	for _, want := range t.config.GetCertificateAtIndex(t.sniIndex).signatureSchemes {
		pos := 2
		for pos+2 <= 2+sigAlgsLen && pos+2 <= dataLen {
			scheme := SignatureScheme(binary.BigEndian.Uint16(data[pos : pos+2]))
			if scheme == want {
				t.scheme = scheme
				return
			}
			pos += 2
		}
	}

}

func (t *TLState) handleSupportedVersions(data []byte) {

	dataLen := len(data)

	if dataLen < 1 {
		return
	}

	listLen := int(data[0])

	if !(listLen%2 == 0 && 1+listLen <= dataLen) {
		return
	}

	for i := 0; i < listLen; i += 2 {
		ver := binary.BigEndian.Uint16(data[1+i : 1+i+2])
		if ver != TLS13Version {
			continue
		}

		t.tls13 = true
		return
	}

}

func (t *TLState) handleKeyShare(data []byte) {

	dataLen := len(data)

	if dataLen < 2 {
		return
	}

	ksLen := int(binary.BigEndian.Uint16(data[0:2]))

	for _, want := range t.config.namedGroups {
		pos := 2
		for pos+4 <= 2+ksLen && pos+4 <= dataLen {
			group := NamedGroup(binary.BigEndian.Uint16(data[pos : pos+2]))
			keyLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
			pos += 4
			if pos+keyLen > dataLen {
				break
			}
			if group == want {
				t.peerPublicKey = append(t.peerPublicKey, data[pos:pos+keyLen]...)
				t.namedGroup = group
				return
			}
			pos += keyLen
		}
	}
}

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
