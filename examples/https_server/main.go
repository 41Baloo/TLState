package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/41Baloo/TLState"
	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
		log.Error().Err(err).Msg("Failed to get state")
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
		log.Error().Err(err).Msg("Feed error")
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
				log.Error().Err(err).Msg("Read error")
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
		log.Error().Err(err).Msg("Failed to read request")
		return gnet.Close
	}

	ctx.buff.Reset()

	log.Info().Str("IP", c.RemoteAddr().String()).Str("UserAgent", req.Header.Get("User-Agent")).Str("Path", req.URL.Path)

	switch req.URL.Path {
	case "/":
		ctx.buff.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!"))
	default:
		ctx.buff.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}

	err = ctx.state.Write(ctx.buff)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write")
		return gnet.Close
	}

	c.Write(ctx.buff.B)
	ctx.buff.Reset()

	return gnet.None
}

func init() {

	log.Logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05",
	}).With().Timestamp().Caller().Logger()

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

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

	log.Info().Err(gnet.Run(hs, hs.addr, []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
		gnet.WithReuseAddr(true),
		gnet.WithTCPKeepAlive(1 * time.Minute),
	}...)).Msg("Server Exits")
}
