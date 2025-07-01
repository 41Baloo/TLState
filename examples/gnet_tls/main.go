package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"time"

	_ "net/http/pprof"

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
	if err != nil {
		log.Println(err)
		return gnet.Close
	}

	if resp == TLState.Responded {
		c.Write(ctx.buff.B)
		return gnet.None
	}

	if !ctx.state.IsHandshakeDone() {
		return gnet.None
	}

	ctx.buff.Reset()

	for {
		// Since Read does not replace but append, we can call it repeatetly until we read all packets, to batch a single response
		resp, err = ctx.state.Read(ctx.buff)
		if err != nil {
			log.Println(err)
			return gnet.None
		}

		if resp != TLState.Responded {
			break
		}
	}

	if ctx.buff.Len() == 0 {
		return gnet.None
	}

	log.Printf("%s (%s -> %s) => %s", c.RemoteAddr(), ctx.state.GetSelectedNamedGroup().String(), ctx.state.GetSelectedCipher().String(), string(ctx.buff.B))

	err = ctx.state.Write(ctx.buff)
	if err != nil {
		log.Println(err)
		return gnet.Close
	}

	c.Write(ctx.buff.B)
	ctx.buff.Reset()

	return gnet.None
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	config, err := TLState.ConfigFromFile("server.crt", "server.key")
	if err != nil {
		panic(err)
	}
	CONFIG = config
}

func main() {
	var port int
	var multicore bool

	flag.IntVar(&port, "port", 8443, "server port")
	flag.BoolVar(&multicore, "multicore", true, "multicore")
	flag.Parse()

	opts := []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
		gnet.WithReuseAddr(true),
		gnet.WithTCPKeepAlive(1 * time.Minute),
	}

	hs := &HTTPServer{addr: fmt.Sprintf("tcp://:%d", port), multicore: multicore}

	log.Println("server exits:", gnet.Run(hs, hs.addr, opts...))
}
