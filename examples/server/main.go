package main

import (
	"io"
	"log"
	"net"

	"github.com/41Baloo/TLState"
	"github.com/41Baloo/TLState/byteBuffer"
)

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
		resp, err := state.Feed(buf)
		if resp == TLState.Responded { // First check for response status
			c.Write(buf.B)
		}
		if err != nil { // The handle errors
			if err != io.EOF {
				log.Printf("Error Feeding: %s", err.Error())
			}
			c.Close()
			return
		}
		buf.Reset()

		if !state.IsHandshakeDone() {
			continue
		}

		// Once handshake is done, decrypt incoming...
		for {
			resp, err := state.Read(buf)
			if err != nil {
				if buf.Len() != 0 {
					// Respond with leftover responded data before bailing
					c.Write(buf.B)
				}
				log.Printf("Error Reading: %s", err.Error())
				return
			}
			if resp != TLState.Responded {
				break
			}
		}

		if buf.Len() > 0 {
			// buf.B now contains plaintext application data
			log.Printf("%s => %s", c.RemoteAddr(), buf)
			// echo back encrypted
			err := state.Write(buf)
			if err != nil {
				log.Printf("Error Writing: %s", err.Error())
				return
			}
			c.Write(buf.B)
		}
		buf.Reset()

	}
}
