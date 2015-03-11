/*
 * Copyright (c) 2015 YAMAMOTO Masaya <pandax381@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type Config struct {
	ListenAddr string
	SourceAddr string
	RemoteAddr string
	TLSAccept  bool
	TLSKey     string
	TLSCert    string
	TLSConnect bool
}

type Proxy struct {
	conf Config
	cert tls.Certificate
	quit chan bool
}

func NewProxy(conf Config) *Proxy {
	var cert tls.Certificate
	if conf.TLSAccept {
		var err error
		cert, err = tls.LoadX509KeyPair(conf.TLSCert, conf.TLSKey)
		if err != nil {
			log.Println(err)
			return nil
		}
	}
	return &Proxy{
		conf: conf,
		cert: cert,
		quit: make(chan bool),
	}
}

func (p *Proxy) Run() {
	listener, err := net.Listen("tcp", p.conf.ListenAddr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Listen on %s\n", listener.Addr())
	complete := make(chan bool)
	go func() {
		wg := &sync.WaitGroup{}
		quit := make(chan bool)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() {
					continue
				}
				listener.Close()
				close(quit)
				wg.Wait()
				close(complete)
				return
			}
			wg.Add(1)
			go p.handle(conn, wg, quit)
		}
	}()
	for {
		select {
		case <-p.quit:
			listener.Close()
		case <-complete:
			return
		}
	}
	// does not reach
}

func (p *Proxy) handle(conn1 net.Conn, wg *sync.WaitGroup, quit chan bool) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
		wg.Done()
		log.Println("Close Session")
	}()
	log.Println("Accept New Session")
	if p.conf.TLSAccept {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{p.cert},
		}
		conn1 = tls.Server(conn1, tlsConfig)
	}
	defer conn1.Close()
	log.Println("Connect Remote Host")
	saddr, err := net.ResolveTCPAddr("tcp", p.conf.SourceAddr)
	if err != nil {
		log.Println(err)
		return
	}
	raddr, err := net.ResolveTCPAddr("tcp", p.conf.RemoteAddr)
	if err != nil {
		log.Println(err)
		return
	}
	var conn2 net.Conn
	conn2, err = net.DialTCP("tcp", saddr, raddr)
	if err != nil {
		log.Println(err)
		return
	}
	if p.conf.TLSConnect {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn2 = tls.Client(conn2, tlsConfig)
	}
	defer conn2.Close()
	complete := make(chan int64)
	go transfer(conn1, conn2, complete)
	go transfer(conn2, conn1, complete)
	for n := 2; n > 0; n-- {
		select {
		case <-complete:
			break
		case <-quit:
			conn1.Close()
			conn2.Close()
			for ; n > 0; n-- {
				<-complete
			}
			return
		}
	}
}

func transfer(dst, src net.Conn, complete chan<- int64) {
	n, err := io.Copy(dst, src)
	if err != nil {
		log.Println(err)
		if e, ok := err.(*net.OpError); ok && e.Err == syscall.EPIPE {
			if _, ok := src.(*net.TCPConn); ok {
				src.(*net.TCPConn).CloseRead()
			} else {
				src.Close()
			}
		}
	}
	if _, ok := dst.(*net.TCPConn); ok {
		dst.(*net.TCPConn).CloseWrite()
	} else {
		dst.Close()
	}
	complete <- n
}

func (p *Proxy) Shutdown() {
	close(p.quit)
}

func main() {
    config := Config{}
	flag.StringVar(&config.ListenAddr, "l", ":8000", "Listen Address")
	flag.StringVar(&config.SourceAddr, "s", "", "Source Address")
	flag.StringVar(&config.RemoteAddr, "r", "localhost:8080", "Remote Address")
	flag.BoolVar(&config.TLSAccept, "tls-accept", false, "Enable TLS Accept")
	flag.StringVar(&config.TLSCert, "tls-cert", "./server.crt", "Certificate File")
	flag.StringVar(&config.TLSKey,  "tls-key", "./server.key", "Privatekey File")
	flag.BoolVar(&config.TLSConnect, "tls-connect", false, "Enable TLS Connect")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println("PID:", os.Getpid())

	proxy := NewProxy(config)
	complete := make(chan bool)
	go func() {
		defer close(complete)
		proxy.Run()
	}()
	sigch := make(chan os.Signal)
	signal.Notify(sigch, os.Interrupt)
	for {
		select {
		case s := <-sigch:
			log.Println("Recieve signal:", s)
			proxy.Shutdown()
		case <-complete:
			log.Println("Good bye")
			return
		}
	}
	// does not reach
}
