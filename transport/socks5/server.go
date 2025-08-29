// Copyright 2023 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type Server struct {
	streamDialer transport.StreamDialer
	packetProxy  network.PacketProxy
	listener     net.Listener
	auth         Authenticator
	mu           sync.RWMutex
	closed       bool
}

type Authenticator interface {
	Authenticate(username, password []byte) bool
	Method() byte
}

type NoAuthenticator struct{}

func (NoAuthenticator) Authenticate(username, password []byte) bool { return true }
func (NoAuthenticator) Method() byte                                { return authMethodNoAuth }

type UserPassAuthenticator struct {
	credentials map[string]string
}

func NewUserPassAuthenticator(creds map[string]string) *UserPassAuthenticator {
	return &UserPassAuthenticator{credentials: creds}
}

func (u *UserPassAuthenticator) Authenticate(username, password []byte) bool {
	if pass, ok := u.credentials[string(username)]; ok {
		return pass == string(password)
	}
	return false
}

func (u *UserPassAuthenticator) Method() byte { return authMethodUserPass }

func NewServer(streamDialer transport.StreamDialer, packetProxy network.PacketProxy, auth Authenticator) *Server {
	if auth == nil {
		auth = NoAuthenticator{}
	}
	return &Server{
		streamDialer: streamDialer,
		packetProxy:  packetProxy,
		auth:         auth,
	}
}

func (s *Server) ListenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	s.listener = listener
	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	s.listener = listener
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := s.handleMethodSelection(conn); err != nil {
		return
	}

	if s.auth.Method() == authMethodUserPass {
		if err := s.handleAuthentication(conn); err != nil {
			return
		}
	}

	s.handleRequest(conn)
}

func (s *Server) handleMethodSelection(conn net.Conn) error {
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return fmt.Errorf("failed to read method selection")
	}

	if buf[0] != 5 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if n < 2+nmethods {
		return fmt.Errorf("incomplete method selection")
	}

	authMethod := s.auth.Method()
	methodSupported := false
	for i := 0; i < nmethods; i++ {
		if buf[2+i] == authMethod {
			methodSupported = true
			break
		}
	}

	response := []byte{5, authMethod}
	if !methodSupported {
		response[1] = 0xFF
	}

	_, err = conn.Write(response)
	if !methodSupported {
		return fmt.Errorf("no acceptable authentication methods")
	}
	return err
}

func (s *Server) handleAuthentication(conn net.Conn) error {
	buf := make([]byte, 513)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return fmt.Errorf("failed to read authentication request")
	}

	if buf[0] != 1 {
		return fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	ulen := int(buf[1])
	if n < 2+ulen+1 {
		return fmt.Errorf("incomplete authentication request")
	}

	username := buf[2 : 2+ulen]
	plen := int(buf[2+ulen])
	if n < 2+ulen+1+plen {
		return fmt.Errorf("incomplete authentication request")
	}

	password := buf[2+ulen+1 : 2+ulen+1+plen]

	success := s.auth.Authenticate(username, password)
	status := byte(0)
	if !success {
		status = 1
	}

	response := []byte{1, status}
	_, err = conn.Write(response)
	if !success {
		return fmt.Errorf("authentication failed")
	}
	return err
}

func (s *Server) handleRequest(conn net.Conn) {
	buf := make([]byte, 262)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		s.sendReply(conn, ErrGeneralServerFailure, "0.0.0.0:0")
		return
	}

	if buf[0] != 5 {
		s.sendReply(conn, ErrGeneralServerFailure, "0.0.0.0:0")
		return
	}

	cmd := buf[1]

	addr, err := readAddr(&bufferReader{buf: buf[3:n], pos: 0})
	if err != nil {
		s.sendReply(conn, ErrAddressTypeNotSupported, "0.0.0.0:0")
		return
	}

	dstAddr := addrToString(addr)

	switch cmd {
	case CmdConnect:
		s.handleConnect(conn, dstAddr)
	case CmdUDPAssociate:
		s.handleUDPAssociate(conn, dstAddr)
	default:
		s.sendReply(conn, ErrCommandNotSupported, "0.0.0.0:0")
	}
}

type bufferReader struct {
	buf []byte
	pos int
}

func (b *bufferReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.pos:])
	b.pos += n
	return n, nil
}

func (s *Server) handleConnect(clientConn net.Conn, dstAddr string) {
	targetConn, err := s.streamDialer.DialStream(context.Background(), dstAddr)
	if err != nil {
		s.sendReply(clientConn, ErrHostUnreachable, "0.0.0.0:0")
		return
	}
	defer targetConn.Close()

	if err := s.sendReply(clientConn, 0, targetConn.LocalAddr().String()); err != nil {
		return
	}

	relayConnections(clientConn, targetConn)
}

func (s *Server) handleUDPAssociate(clientConn net.Conn, dstAddr string) {
	localAddr := s.listener.Addr().String()
	if err := s.sendReply(clientConn, 0, localAddr); err != nil {
		return
	}

	buf := make([]byte, 1)
	clientConn.Read(buf)
}

func (s *Server) sendReply(conn net.Conn, replyCode ReplyCode, bindAddr string) error {
	reply := []byte{5, byte(replyCode), 0}
	
	replyWithAddr, err := appendSOCKS5Address(reply, bindAddr)
	if err != nil {
		replyWithAddr = append(reply, 1, 0, 0, 0, 0, 0, 0)
	}
	
	_, err = conn.Write(replyWithAddr)
	return err
}

func relayConnections(conn1, conn2 net.Conn) {
	go func() {
		defer conn1.Close()
		defer conn2.Close()
		io.Copy(conn1, conn2)
	}()
	
	defer conn1.Close()
	defer conn2.Close()
	io.Copy(conn2, conn1)
}
