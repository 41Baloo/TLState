package main

import (
	"log"
	"net"

	"github.com/41Baloo/TLState"
	"github.com/41Baloo/TLState/byteBuffer"
)

func main() {
	// 1. Load your cert + key
	cfg, err := TLState.ConfigFromFile("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	// 2. Accept connections in plain TCP…
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

		// Once handshake is done, decrypt incoming…
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
				// …echo back encrypted
				state.Write(buf)
				c.Write(buf.B)
			}
			buf.Reset()
		}
	}
}
