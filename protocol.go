package TLState

const (
	ProtocolVersion = 0x0303 // Backwards compatibility
	TLS13Version    = 0x0304
)

func marshallAdditionalData(length int) []byte {
	return []byte{ // Escapes to heap
		byte(RecordTypeApplicationData),
		byte(ProtocolVersion >> 8),
		byte(ProtocolVersion & 0xFF),
		byte(length >> 8),
		byte(length & 0xFF),
	}
}
