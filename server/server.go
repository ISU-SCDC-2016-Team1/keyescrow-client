package server

import (
	"fmt"
	"log"
	"net"
	"time"

	zmq "github.com/pebbe/zmq3"
)

const (
	GITLABKEY       = "UyrcEQzJwmoaEiTHtRjf"
	GITLAB_USER_URL = "http://gitlab/api/v3/users?username=%v&private_token=%v"
	GITLAB_USER_KEY = "http://gitlab/api/v3/users/%d/keys?private_token=%v"
)

type authinfo struct {
	Token  string
	Issued time.Time
}

var authTable map[string][]authinfo = make(map[string][]authinfo)

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
