package TLState

import (
	"unsafe"
	_ "unsafe"
)

//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

func GetHeadTail(i int, head []byte, tail []byte) byte {
	if i < len(head) {
		return head[i]
	}
	return tail[i-len(head)]
}

// Should always get inlined, so no heap allocs (except append path, obviously)
func EnsureLen(b []byte, n int) []byte {
	if n <= cap(b) {
		// Backing array is big enough
		return b[:n]
	}
	// Grow via append (this *should* continue using the same backing array)
	return append(b, make([]byte, n-len(b))...)
}

// Fastest way i found to zero a slice
func ZeroSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)))
}
