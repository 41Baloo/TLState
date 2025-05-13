package byteBuffer

import "github.com/valyala/bytebufferpool"

// Thanks to gnet
type ByteBuffer = bytebufferpool.ByteBuffer

var (
	Get = bytebufferpool.Get
	Put = func(b *ByteBuffer) {
		if b != nil {
			bytebufferpool.Put(b)
		}
	}
)
