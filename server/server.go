package server

import (
	"fmt"
	"log"
	"net"

	zmq "github.com/pebbe/zmq3"
)

type Server struct {
	Responder *zmq.Socket
	Keydir    string
}

func New(addr *net.TCPAddr) (*Server, error) {
	sock, err := zmq.NewSocket(zmq.REP)
	sock.Bind(fmt.Sprintf("tcp://%v", addr))
	log.Printf("Listening on %v", addr)
	return &Server{
		Responder: sock,
	}, err
}

func (s *Server) Close() {
	s.Responder.Close()
}
