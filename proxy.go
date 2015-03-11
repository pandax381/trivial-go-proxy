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

type config struct {
	laddr      string
	saddr      string
	raddr      string
	tlsAccept  bool
	tlsKey     string
	tlsCert    string
	tlsConnect bool
}

type proxy struct {
	conf config
	quit chan bool
}

func NewProxy(conf config) *proxy {
	return &proxy{
		conf: conf,
		quit: make(chan bool),
	}
}

func (p *proxy) Run() {
	listener, err := net.Listen("tcp", p.conf.laddr)
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

func (p *proxy) handle(conn1 net.Conn, wg *sync.WaitGroup, quit chan bool) {
	defer wg.Done()
	defer log.Println("Close Session")
	log.Println("Accept New Session")
	if p.conf.tlsAccept {
		cert, err := tls.LoadX509KeyPair(p.conf.tlsCert, p.conf.tlsKey)
		if err != nil {
			log.Println(err)
			conn1.Close()
			return
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		conn1 = tls.Server(conn1, tlsConfig)
	}
	log.Println("Connect Remote Host")
	saddr, err := net.ResolveTCPAddr("tcp", p.conf.saddr)
	if err != nil {
		log.Println(err)
		conn1.Close()
		return
	}
	raddr, err := net.ResolveTCPAddr("tcp", p.conf.raddr)
	if err != nil {
		log.Println(err)
		conn1.Close()
		return
	}
	var conn2 net.Conn
	conn2, err = net.DialTCP("tcp", saddr, raddr)
	if err != nil {
		log.Println(err)
		conn1.Close()
		return
	}
	if p.conf.tlsConnect {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn2 = tls.Client(conn2, tlsConfig)
	}
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
	// just in case
	conn1.Close()
	conn2.Close()
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

func (p *proxy) shutdown() {
	close(p.quit)
}

func main() {
	laddr := flag.String("l", ":8000", "Listen Address")
	saddr := flag.String("s", "", "Source Address")
	raddr := flag.String("r", "localhost:8080", "Remote Address")
	tlsAccept := flag.Bool("tls-accept", false, "Enable TLS Accept")
	tlsCert := flag.String("tls-cert", "./server.crt", "Certificate File")
	tlsKey := flag.String("tls-key", "./server.key", "Privatekey File")
	tlsConnect := flag.Bool("tls-connect", false, "Enable TLS Connect")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println("PID:", os.Getpid())

	config := config{
		laddr:      *laddr,
		saddr:      *saddr,
		raddr:      *raddr,
		tlsAccept:  *tlsAccept,
		tlsCert:    *tlsCert,
		tlsKey:     *tlsKey,
		tlsConnect: *tlsConnect,
	}
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
			proxy.shutdown()
		case <-complete:
			log.Println("Good bye")
			return
		}
	}
	// does not reach
}
