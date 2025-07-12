package TLState

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"io"

	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/rs/zerolog/log"
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

func (t *TLState) BuildHandshakeMessage(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) (ResponseState, error) {

	marshallHandshake(msgType, inOut)

	if t.handshakeState < HandshakeStateServerHelloDone {
		return BuildRecordMessage(RecordTypeHandshake, inOut), nil
	}

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

	// See tlstate.go:encryptRecord to understand this hack better
	fLength := inOut.Len()
	inOut.B = EnsureLen(inOut.B, fLength+messageLength+t.handshakeCipher.Overhead())

	ciphertext := t.handshakeCipher.Seal(inOut.B[fLength:fLength], nonce, inOut.B[:messageLength], additionalData)

	// No longer need the input, time to replace it with the output.
	inOut.Reset()
	inOut.Write(additionalData)
	inOut.Write(ciphertext)

	return Responded, nil
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

func (t *TLState) processHandshake(in *byteBuffer.ByteBuffer) (ResponseState, error) {
	for {
		in.Reset()
		if t.handshakeState == HandshakeStateDone {
			return None, nil
		}

		buffered := t.incoming.Buffered()
		if buffered < 5 {
			break
		}

		head, tail := t.incoming.Peek(5)
		recType := RecordType(head[0])

		b0 := GetHeadTail(2, head[1:], tail)
		b1 := GetHeadTail(3, head[1:], tail)

		length := int(binary.BigEndian.Uint16([]byte{b0, b1}))

		if buffered < 5+length {
			break
		}

		rawHeader := make([]byte, 5)
		t.incoming.Read(rawHeader)

		head, tail = t.incoming.Peek(length)
		t.incoming.Discard(length)
		in.Write(head)
		in.Write(tail)

		switch recType {
		case RecordTypeChangeCipher:
			continue

		case RecordTypeHandshake:
			return t.processHandshakeMessage(in)

		case RecordTypeApplicationData:
			if t.handshakeState >= HandshakeStateServerHelloDone {
				return None, t.processEncryptedHandshake(in, rawHeader)
			} else {
				in.Reset()
				t.BuildAlert(AlertLevelFatal, AlertDescriptionUnexpectedMessage, in)
				return Responded, ErrApplicationDataDuringHandshake
			}

		case RecordTypeAlert:
			err := t.handleAlert(in.B)
			if err != nil {
				return None, err
			}

		default:
			in.Reset()
			t.BuildAlert(AlertLevelFatal, AlertDescriptionUnexpectedMessage, in)
			return Responded, ErrUnknownRecordType
		}
	}

	return None, nil
}

func (t *TLState) processHandshakeMessage(out *byteBuffer.ByteBuffer) (ResponseState, error) {
	// Handshake headers are at least 4 bytes
	dataLen := out.Len()
	if dataLen < 4 {
		return None, nil
	}

	msgType := out.B[0]
	length := uint32(out.B[1])<<16 | uint32(out.B[2])<<8 | uint32(out.B[3])

	if dataLen < int(4+length) {
		return None, nil
	}

	switch HandshakeType(msgType) {
	case HandshakeTypeClientHello:
		t.handshakeMessages.Write(out.B[:4+length])
		out.B = out.B[4 : 4+length]

		return t.processClientHello(out)
	default:
		log.Warn().Uint8("handshake_type", msgType).Msg("Unexpected handshake message type")
		return None, nil
	}
}

func (t *TLState) processEncryptedHandshake(in *byteBuffer.ByteBuffer, header []byte) error {

	inLength := in.Len()
	in.Write(t.clientHandshakeIV)
	nonce := in.B[inLength:]

	in.Write(header)
	additionalData := in.B[inLength+12:]

	nonceCount := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceCount, t.clientRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.clientRecordCount++

	aead, err := t.createAEAD(t.clientHandshakeKey)
	if err != nil {
		return err
	}

	plaintext, err := aead.Open(nil, nonce, in.B[:inLength], additionalData)
	if err != nil {
		return err
	}

	if len(plaintext) == 0 {
		log.Warn().Msg("Empty plaintext after decryption")
		return nil
	}

	contentType := RecordType(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-1]

	switch contentType {
	case RecordTypeHandshake:
		if len(plaintext) >= 4 && plaintext[0] == byte(HandshakeTypeFinished) {
			return t.processClientFinished(plaintext)
		}
	case RecordTypeAlert:
		return t.handleAlert(plaintext)
	default:
		log.Warn().
			Uint8("content_type", uint8(contentType)).
			Uint8("first_byte", plaintext[0]).
			Msg("Not a Finished message")
	}

	return nil
}

func (t *TLState) processClientHello(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	dataLen := out.Len()
	if dataLen < 34 {
		return None, nil
	}

	// clientVersion := binary.BigEndian.Uint16(data.B[0:2]) // ignored in TLS1.3
	copy(t.clientRandom, out.B[2:34])

	// SessionID
	sessionIDLength := int(out.B[34])
	if dataLen < 35+sessionIDLength {
		return None, nil
	}
	t.sessionID = append(t.sessionID, out.B[35:35+sessionIDLength]...)

	offset := 35 + sessionIDLength
	if dataLen < offset+2 {
		return None, nil
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(out.B[offset : offset+2]))
	offset += 2
	if dataLen < offset+cipherSuitesLength {
		return None, nil
	}

	// Pick from our supported ciphers, this allows our config to specify a preference but fallback on the other, in case
	// the client doesnt support our prefered choice
ciphers:
	for _, want := range t.config.ciphers {
		for i := 0; i+1 < cipherSuitesLength; i += 2 {
			suite := CipherSuite(binary.BigEndian.Uint16(out.B[offset+i : offset+i+2]))
			if suite == want {
				t.cipher = suite
				break ciphers
			}
		}
	}
	if t.cipher == 0 {
		out.Reset()
		t.BuildAlert(AlertLevelFatal, AlertDescriptionHandshakeFailure, out)
		return Responded, ErrCiphersNotSupported
	}
	offset += cipherSuitesLength

	// CompressionMethods
	if dataLen < offset+1 {
		return None, nil
	}
	cmLen := int(out.B[offset])
	offset += 1 + cmLen
	if dataLen < offset+2 {
		return None, nil
	}

	// Extensions
	extTotalLen := int(binary.BigEndian.Uint16(out.B[offset : offset+2]))
	offset += 2
	if dataLen < offset+extTotalLen {
		return None, nil
	}
	extEnd := offset + extTotalLen

	for offset < extEnd {
		// need at least 4 bytes for type+length
		if offset+4 > dataLen {
			break
		}
		extType := Extension(binary.BigEndian.Uint16(out.B[offset : offset+2]))
		extLen := int(binary.BigEndian.Uint16(out.B[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > dataLen {
			break
		}
		data := out.B[offset : offset+extLen]

		// Sadly we cant have this in extensions.go, since for statements are never inlined
		switch extType {
		case ExtensionServerName:
			dataLen := len(data)

			if dataLen < 2 || !t.config.sni {
				goto exDone
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
					goto exDone
				}
				pos += nameLen
			}
		case ExtensionSignatureAlgorithms:
			dataLen := len(data)

			if dataLen < 2 {
				goto exDone
			}

			sigAlgsLen := int(binary.BigEndian.Uint16(data[0:2]))

			for _, want := range t.config.GetCertificateAtIndex(t.sniIndex).signatureSchemes {
				pos := 2
				for pos+2 <= 2+sigAlgsLen && pos+2 <= dataLen {
					scheme := SignatureScheme(binary.BigEndian.Uint16(data[pos : pos+2]))
					if scheme == want {
						t.scheme = scheme
						goto exDone
					}
					pos += 2
				}
			}
		case ExtensionSupportedVersions:
			dataLen := len(data)

			if dataLen < 1 {
				goto exDone
			}

			listLen := int(data[0])

			if !(listLen%2 == 0 && 1+listLen <= dataLen) {
				goto exDone
			}

			for i := 0; i < listLen; i += 2 {
				ver := binary.BigEndian.Uint16(data[1+i : 1+i+2])
				if ver != TLS13Version {
					continue
				}

				t.tls13 = true
				goto exDone
			}

		case ExtensionKeyShare:
			dataLen := len(data)

			if dataLen < 2 {
				goto exDone
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
						goto exDone
					}
					pos += keyLen
				}
			}
		}

	exDone:

		offset += extLen
	}

	// We no longer need any input from hereon out. Simply re-use this buffer for our output
	out.Reset()

	if !t.tls13 {
		t.BuildAlert(AlertLevelFatal, AlertDescriptionProtocolVersion, out)
		log.Warn().Msg("Client does not support TLS 1.3")
		return Responded, ErrTLS13NotSupported
	}

	if t.namedGroup == 0 {
		// RFC suggest we MAY send a RetryRequest, we won't for now tho
		t.BuildAlert(AlertLevelFatal, AlertDescriptionHandshakeFailure, out)
		return Responded, ErrNamedGroupsNotSupported
	}

	err := t.setupHandshakeKeys()
	if err != nil {
		t.BuildAlert(AlertLevelFatal, AlertDescriptionIllegalParameter, out)
		return Responded, err
	}

	if t.scheme == 0 {
		t.BuildAlert(AlertLevelFatal, AlertDescriptionHandshakeFailure, out)
		return Responded, ErrSchemesNotSupported
	}

	t.handshakeState = HandshakeStateClientHelloDone

	return t.generateServerResponse(out)
}

// ServerHello + ChangeCipher + FinishedRecord
func (t *TLState) generateServerResponse(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	resp, err := t.generateServerHello(out)
	if err != nil {
		return resp, err
	}

	t.handshakeMessages.Write(out.B[5:]) // Skip record header

	err = t.calculateHandshakeKeys()
	if err != nil {
		return None, nil
		out.Reset()
		t.BuildAlert(AlertLevelFatal, AlertDescriptionIllegalParameter, out)
		return Responded, err
	}

	t.generateChangeCipherSpec(out)
	resp, err = t.generateEncryptedExtensionsRecord(out)
	if err != nil {
		return resp, err
	}
	resp, err = t.generateCertificateRecord(out)
	if err != nil {
		return resp, err
	}
	resp, err = t.generateCertificateVerifyRecord(out)
	if err != nil {
		return resp, err
	}
	t.generateFinishedRecord(out)

	t.handshakeState = HandshakeStateWaitClientFinished

	return Responded, nil
}

// Write serverHello info buffer
func (t *TLState) generateServerHello(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	// Ensure we have enough space for 2 bytes + 32 bytes of serverRandom + 1 byte sessionID length
	out.B = EnsureLen(out.B, 35)

	// Skip 2 bytes ahead and fill serverRandom
	_, err := io.ReadFull(rand.Reader, out.B[2:34])
	if err != nil {
		return None, err
	}

	// Legacy version (TLS 1.2)
	out.B[0] = 0x03
	out.B[1] = 0x03

	// Directly write sessionID length, skips 1 bounds check
	out.B[34] = byte(len(t.sessionID))
	out.Write(t.sessionID)

	// Our negotiated cipher
	out.Write(t.cipher.ToBytes())
	out.WriteByte(0x00)

	t.generateServerHelloExtensions(out)

	t.BuildHandshakeMessage(HandshakeTypeServerHello, out)

	t.handshakeState = HandshakeStateServerHelloDone

	return Responded, nil
}

func (t *TLState) generateChangeCipherSpec(out *byteBuffer.ByteBuffer) ResponseState {
	// Change cipher spec for compatibility with middleboxes

	buff := byteBuffer.Get()
	buff.Write([]byte{0x01})

	resp := BuildRecordMessage(RecordTypeChangeCipher, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp
}

func (t *TLState) generateEncryptedExtensionsRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	buff := byteBuffer.Get()
	buff.Write([]byte{
		0x00, 0x00, // We don't support any extensions
	})

	resp, err := t.BuildHandshakeMessage(HandshakeTypeEncryptedExtensions, buff)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp, nil
}

func (t *TLState) generateCertificateRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	buff := byteBuffer.Get()

	// CertificateRecord doesn't change from connection to connection (i think), so we just precalculate it in our config
	buff.Write(t.config.GetCertificateAtIndex(t.sniIndex).certificateRecord)

	resp, err := t.BuildHandshakeMessage(HandshakeTypeCertificate, buff)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp, nil
}

func (t *TLState) generateCertificateVerifyRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	outLength := out.Len()

	transcriptHash, _ := t.calculateTranscriptHash()

	// Build the context string as per RFC8446
	context := []byte("TLS 1.3, server CertificateVerify")
	contextLen := len(context)

	out.B = EnsureLen(out.B, outLength+64+len(context)+1+len(transcriptHash))
	buf := out.B[outLength:]

	// 64 0x20 bytes (space)
	for i := 0; i < 64; i++ {
		buf[i] = 0x20
	}
	copy(buf[64:], context)
	buf[64+contextLen] = 0x00
	copy(buf[64+contextLen+1:], transcriptHash)

	options := t.scheme.GetSignerOpts()
	sHash := options.HashFunc()

	var toSign []byte
	switch sHash {
	case crypto.SHA256:
		tmp := sha256.Sum256(buf)
		toSign = tmp[:]
	case crypto.SHA384:
		tmp := sha512.Sum384(buf)
		toSign = tmp[:]
	case crypto.SHA512:
		tmp := sha512.Sum512(buf)
		toSign = tmp[:]
	case 0:
		toSign = buf
	}

	// We no longer need buf at this point, simply reset the length to what it was before to continue using the buffer
	out.B = out.B[:outLength]
	out.Write(toSign[:])

	signature, err := t.config.GetCertificateAtIndex(t.sniIndex).parsedKey.Sign(rand.Reader, out.B[outLength:], options)
	if err != nil {
		return None, err
	}
	out.B = out.B[:outLength]

	out.B = EnsureLen(out.B, outLength+2+2+len(signature))
	signatureBytes := out.B[outLength:]

	signatureScheme := t.scheme.ToBytesConst()

	copy(signatureBytes[0:2], signatureScheme)

	binary.BigEndian.PutUint16(signatureBytes[2:4], uint16(len(signature)))

	copy(signatureBytes[4:], signature)

	buff := byteBuffer.Get()
	buff.Write(signatureBytes)

	out.B = out.B[:outLength]

	resp, err := t.BuildHandshakeMessage(HandshakeTypeCertificateVerify, buff)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp, nil
}

func (t *TLState) generateFinishedRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	buff := byteBuffer.Get()
	resp, err := t.calculateVerifyData(buff, t.serverHandshakeTrafficSecret)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}

	resp, err = t.BuildHandshakeMessage(HandshakeTypeFinished, buff)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)
	return resp, nil
}

func (t *TLState) processClientFinished(data []byte) error {

	if len(data) < 4 {
		return nil
	}

	msgType := HandshakeType(data[0])
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	if msgType != HandshakeTypeFinished {
		log.Warn().
			Uint8("msg_type", uint8(msgType)).
			Msg("Expected Finished message, got something else")
		return nil
	}

	if len(data) < int(4+length) {
		return nil
	}

	verifyData := data[4 : 4+length]

	buff := byteBuffer.Get()

	_, err := t.calculateVerifyData(buff, t.clientHandshakeTrafficSecret)
	if err != nil {
		byteBuffer.Put(buff)
		return err
	}

	if !hmac.Equal(verifyData, buff.B) {
		log.Warn().
			Hex("received", verifyData).
			Hex("expected", buff.B).
			Msg("Client Finished verify data mismatch")

		byteBuffer.Put(buff)
		return ErrClientFinishVerifyMissmatch
	}
	byteBuffer.Put(buff)

	t.calculateApplicationKeys()

	t.handshakeMessages.Write(data)

	return nil
}
