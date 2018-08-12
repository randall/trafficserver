package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

var (
	connectFlag = flag.String("connect", "127.0.0.1:8175", "connect to this IP:port")
	hostFlag    = flag.String("host", "localhost", "connect to this IP:port")
	fileName    = flag.String("filename", "", "filename of file list")
	loop        = flag.Int("loop", 1, "Number of times to loop")
)

type ProtocolClient struct {
	conn net.Conn
	host string
}

func NewProtocolClient(address, host string) (*ProtocolClient, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return &ProtocolClient{conn: conn, host: host}, nil
}

func (p *ProtocolClient) RequestFile(filename string) ([]byte, error) {
	req := fmt.Sprintf("%s %s \r\n\r\n", p.host, filename)
	//	log.Printf("Sending %q", req)
	if _, err := p.conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	return ioutil.ReadAll(p.conn)
}

func main() {
	flag.Parse()

	log.Printf("Connecting to %s", *connectFlag)
	/*
		conn, err := net.Dial("tcp", *connectFlag)
		if err != nil {
			log.Fatal(err)
		}
	*/
	if len(*fileName) == 0 {
		log.Fatal("--filename is required")
	}
	reader, err := os.Open(*fileName)
	if err != nil {
		log.Fatal(err)
	}

	var fileNames []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		srcName := scanner.Text()
		fileNames = append(fileNames, strings.TrimSpace(srcName))
	}

	for i := 0; i < *loop; i++ {
		for _, f := range fileNames {
			client, err := NewProtocolClient(*connectFlag, *hostFlag)
			if err != nil {
				log.Fatal(err)
			}

			if out, err := client.RequestFile(f); err != nil {
				log.Printf("ERROR: Requesting %s (iteration=%d): %s", f, i, err)
			} else {
				log.Printf("Got %d bytes for %s", len(out), f)
			}
			client.conn.Close()
		}
	}
}
