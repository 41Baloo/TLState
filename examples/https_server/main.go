package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"

	"github.com/41Baloo/TLState"
	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/panjf2000/gnet/v2"
)

type HTTPServer struct {
	gnet.BuiltinEventEngine

	addr      string
	multicore bool
}

var CONFIG *TLState.Config

type CTX struct {
	state *TLState.TLState
	buff  *byteBuffer.ByteBuffer
}

func (s *HTTPServer) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {

	state, err := TLState.Get()
	if err != nil {
		log.Println("Failed to Get state", err)
		return nil, gnet.Close
	}

	state.SetConfig(CONFIG)

	c.SetContext(&CTX{
		state: state,
		buff:  byteBuffer.Get(),
	})
	return nil, gnet.None
}

func (s *HTTPServer) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx := c.Context().(*CTX)
	TLState.Put(ctx.state)
	byteBuffer.Put(ctx.buff)

	return gnet.Close
}

func (s *HTTPServer) OnTraffic(c gnet.Conn) gnet.Action {

	ctx := c.Context().(*CTX)
	buf, _ := c.Next(-1)

	ctx.buff.Reset()
	ctx.buff.Write(buf)

	resp, err := ctx.state.Feed(ctx.buff)
	if resp == TLState.Responded {
		c.Write(ctx.buff.B)
	}
	if err != nil {
		log.Printf("Feed error: %s", err.Error())
		return gnet.Close
	}

	if !ctx.state.IsHandshakeDone() {
		return gnet.None
	}

	ctx.buff.Reset()

	for {
		// Since Read does not replace but append, we can call it repeatetly until we read all packets, to batch a single response
		resp, err = ctx.state.Read(ctx.buff)
		if err != nil {
			if ctx.buff.Len() != 0 {
				c.Write(ctx.buff.B)
			}
			if err != io.EOF {
				log.Printf("Read error: %s", err.Error())
			}
			return gnet.Close
		}

		if resp != TLState.Responded {
			break
		}
	}

	if ctx.buff.Len() == 0 {
		return gnet.None
	}

	reader := bufio.NewReader(bytes.NewReader(ctx.buff.B))
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return gnet.None
		}
		log.Printf("Failed to read request: %s", err.Error())
		return gnet.Close
	}

	ctx.buff.Reset()

	log.Printf("%s is requesting '%s' with useragent '%s'", c.RemoteAddr(), req.URL.Path, req.Header.Get("User-Agent"))

	switch req.URL.Path {
	case "/":
		ctx.buff.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!"))
	default:
		ctx.buff.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}

	err = ctx.state.Write(ctx.buff)
	if err != nil {
		log.Printf("Write error: %s", err.Error())
		return gnet.Close
	}

	c.Write(ctx.buff.B)
	ctx.buff.Reset()

	return gnet.None
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	certificate, err := TLState.CreateCertificateFromFile("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	config := TLState.NewConfig(certificate)

	CONFIG = config
}

func main() {
	var port int
	var multicore bool

	flag.IntVar(&port, "port", 8443, "server port")
	flag.BoolVar(&multicore, "multicore", true, "multicore")
	flag.Parse()

	hs := &HTTPServer{addr: fmt.Sprintf("tcp://:%d", port), multicore: multicore}

	log.Println("server exits:", gnet.Run(hs, hs.addr, gnet.WithMulticore(multicore)))
}
