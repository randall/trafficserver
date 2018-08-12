package main

import (
	"bufio"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

var (
	listenFlag = flag.String("listen", "127.0.0.1:8175", "bind to this IP:port")
)

type ProtocolServer struct {
	listener net.Listener
}

func NewProtocolServer(listener net.Listener) *ProtocolServer {
	return &ProtocolServer{listener: listener}
}

func (p *ProtocolServer) Start() error {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			log.Printf("ERROR: %s", err)
			continue
		}
		log.Printf("new connection %q", conn)
		go p.handleConnection(conn)
	}
}

func (p *ProtocolServer) handleConnection(conn net.Conn) {
	r := bufio.NewReader(conn)
	in := make([]byte, 1024)

	for {
		//in, err := ioutil.ReadAll(conn)
		_, err := r.Read(in)
		//line, _, err := r.Read(in)
		switch err {
		case nil:
		case io.EOF:
			fallthrough
		default:
			return
		}
		line := string(in)
		parts := strings.Split(string(line), " ")
		if len(parts) < 2 {
			log.Printf("ERROR: Invalid input %q", line)
			conn.Close()
			return
		}

		filename := parts[1]
		out, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Printf("ERROR: Could not read %q: %s", filename, err)
			conn.Close()
			return
		}

		bytesWritten, err := conn.Write(out)
		if err != nil {
			log.Printf("ERROR: Could not write %q: %s", filename, err)
			conn.Close()
			return
		}

		if bytesWritten != len(out) {
			log.Printf("WARN: Did not write all bytes for %q; wrote %d expected %d", filename, bytesWritten, len(out))
		}

		log.Printf("Wrote %d for %s", bytesWritten, filename)
		conn.Close()
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	listener, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Waiting for connects at %s", *listenFlag)
	server := NewProtocolServer(listener)
	if err = server.Start(); err != nil {
		log.Fatal(err)
	}
}
