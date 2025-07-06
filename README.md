# TLState

A standalone, dependency-free **TLS 1.3** state machine for Go. Ideal for adding TLS support to any byte-oriented transport.

⚠️ **Experimental**: This project is under active development. There may be bugs, edge-case failures, and (possibly) insecure corner-cases. Use at your own risk.

---

## 📦 Features

* **100% [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446) Compliant**: Feel free to open an issue if you find non compliant behaviour
* **Extremely performant**: Almost 2x faster than crypto/tls in some cases
* **Pure state machine**: No built-in networking; you feed/send raw bytes.
* **Zero heap allocations** in hot paths via buffer reuse.
* **Cipher Suites**:

	* `TLS_CHACHA20_POLY1305_SHA256`
	* `TLS_AES_128_GCM_SHA256`
	* `TLS_AES_256_GCM_SHA384`

* **NamedGroups**:

	* `X25519`
	* `P-256` (aka: `secp256r1` / `prime256v1`)

* **SignatureSchemes**:

	* `ECDSA_SECP256R1_SHA256`
	* `ECDSA_SECP384R1_SHA384`
	* `ECDSA_SECP521R1_SHA512`
	* `RSA_PSS_RSAE_SHA256`
	* `RSA_PSS_RSAE_SHA384`
	* `RSA_PSS_RSAE_SHA512`
	* `ED25519`

---

## 🔧 Installation

```bash
go get github.com/41Baloo/TLState
```

---

## 🚀 Quick Start

```go
func main() {
	// 1. Load your cert + key
	certificate, err := TLState.CreateCertificateFromFile("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	cfg := TLState.NewConfig(certificate)

	// 2. Accept connections in plain TCP...
	ln, _ := net.Listen("tcp", ":8443")
	log.Println("TLState server listening via plain TCP on :8443")
	for {
		conn, _ := ln.Accept()
		go handle(conn, cfg)
	}
}

func handle(c net.Conn, cfg *TLState.Config) {
	defer c.Close()

	// 3. Get a fresh state
	state, _ := TLState.Get()
	defer TLState.Put(state)
	state.SetConfig(cfg)

	buf := byteBuffer.Get()
	defer byteBuffer.Put(buf)

	// 4. Loop: read → Feed() → send handshake/data → Read()/Write()
	tmp := make([]byte, 64*1024)
	for {
		n, err := c.Read(tmp)
		if err != nil {
			return
		}
		buf.Write(tmp[:n])

		// Process handshake or pass-through
		if resp, _ := state.Feed(buf); resp == TLState.Responded {
			c.Write(buf.B)
		}
		buf.Reset()

		// Once handshake is done, decrypt incoming...
		if state.IsHandshakeDone() {
			for {
				resp, _ := state.Read(buf)
				if resp != TLState.Responded {
					break
				}
			}

			if buf.Len() > 0 {
				// buf.B now contains plaintext application data
				log.Printf("%s => %s", c.RemoteAddr(), buf)
				// echo back encrypted
				state.Write(buf)
				c.Write(buf.B)
			}
			buf.Reset()
		}
	}
}
```

---

## 📚 API Reference

### `TLState` Lifecycle

| Method                    | Description                                                                   |
| ------------------------- | ----------------------------------------------------------------------------- |
| `TLState.Get() (*State)`  | Acquire a new state (fresh key-pair).                                         |
| `TLState.Put(state)`      | Return to pool, resetting all internal buffers and secrets.                   |
| `state.SetConfig(cfg)`    | Attach your `Config` (cert, key, cipher list). Required before any handshake. |
| `state.IsHandshakeDone()` | Returns `true` once the TLS 1.3 handshake completes.                          |

### Data Flow

| Method                                | Signature                | Action                                                      |
| ------------------------------------- | ------------------------ | ----------------------------------------------------------- |
| `Feed(inOut *byteBuffer.ByteBuffer)`     | `(ResponseState, error)` | Consumes incoming record bytes; may write handshake replies. |
| `Read(out *byteBuffer.ByteBuffer)`    | `(ResponseState, error)` | Decrypts and appends one application-data record into `out`.             |
| `Write(inOut *byteBuffer.ByteBuffer)` | `error`                  | Encrypts plaintext in `inOut` → ciphertext in same buffer.   |

* **Buffers** are from `github.com/valyala/bytebufferpool` and reused intensively.
* Check each call’s `ResponseState` to know if you must send `buffer.B` back over the wire.

---

## 📝 Contributing

You are **very** welcome to contibute and to help us improve TLState. Simply open a PR. However, be aware thatwe make use of some pretty hacky optimizations:

* Many functions write into pre-allocated buffers instead of returning values.

* **Non-standard Control Flow**: For more performance we make use of some pretty hacky optimizations

	* Many functions write into pre-allocated buffers instead of returning values.
	* **ResponseState** return values indicate whether a buffer got filled:

		* `None` → nothing written / should not be used
		* `Responded` → output is ready in your buffer

	* Buffer parameters are (usually) named:

		* `in` buffer will be used to read from
		* `out` buffer will be used to output the result
		* `inOut` buffer will both be used to read and output



> **Disclaimer:** TLState is still a work in progress. It is **not** ready for production use. Always validate security before deploying.
