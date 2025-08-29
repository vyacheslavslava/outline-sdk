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

package mobileproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/network/lwip2transport"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/things-go/go-socks5"
)

type TunDevice struct {
	device       network.IPDevice
	socks5Server *socks5.Server
	listener     net.Listener
	localPort    int
	closed       chan struct{}
}

func NewTunDevice(streamDialer *StreamDialer, packetProxy network.PacketProxy) (*TunDevice, error) {
	if streamDialer == nil {
		return nil, errors.New("streamDialer must not be nil")
	}
	if packetProxy == nil {
		return nil, errors.New("packetProxy must not be nil")
	}

	device, err := lwip2transport.ConfigureDevice(streamDialer.StreamDialer, packetProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to configure tun2socks device: %w", err)
	}

	server := socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" {
				return streamDialer.StreamDialer.DialStream(ctx, addr)
			}
			return nil, fmt.Errorf("unsupported network: %s", network)
		}),
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to create SOCKS5 listener: %w", err)
	}

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		device.Close()
		return nil, fmt.Errorf("failed to parse listener address: %w", err)
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		listener.Close()
		device.Close()
		return nil, fmt.Errorf("failed to parse port: %w", err)
	}

	tunDevice := &TunDevice{
		device:       device,
		socks5Server: server,
		listener:     listener,
		localPort:    port,
		closed:       make(chan struct{}),
	}

	go func() {
		defer listener.Close()
		server.Serve(listener)
	}()

	return tunDevice, nil
}

func (t *TunDevice) GetSOCKS5Port() int {
	return t.localPort
}

func (t *TunDevice) GetSOCKS5Address() string {
	return fmt.Sprintf("127.0.0.1:%d", t.localPort)
}

func (t *TunDevice) Write(packet []byte) (int, error) {
	return t.device.Write(packet)
}

func (t *TunDevice) Read(packet []byte) (int, error) {
	return t.device.Read(packet)
}

func (t *TunDevice) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := t.device.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return 0, errors.New("device does not support WriteTo")
}

func (t *TunDevice) MTU() int {
	return t.device.MTU()
}

func (t *TunDevice) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
	}

	var errs []error
	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.device != nil {
		if err := t.device.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing TunDevice: %v", errs)
	}
	return nil
}

type UDPPacketProxy struct {
	streamDialer transport.StreamDialer
}

func NewUDPPacketProxy(streamDialer transport.StreamDialer) *UDPPacketProxy {
	return &UDPPacketProxy{streamDialer: streamDialer}
}

func (p *UDPPacketProxy) NewSession(respWriter network.PacketResponseReceiver) (network.PacketRequestSender, error) {
	return &udpSession{streamDialer: p.streamDialer}, nil
}

type udpSession struct {
	streamDialer transport.StreamDialer
}

func (s *udpSession) WriteTo(packet []byte, addr netip.AddrPort) (int, error) {
	return 0, errors.New("UDP over SOCKS5 not fully implemented")
}

func (s *udpSession) Close() error {
	return nil
}
