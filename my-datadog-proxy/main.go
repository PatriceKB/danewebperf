package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func handleClient(conn net.Conn) {
	defer conn.Close()

	span := tracer.StartSpan("proxy.request", tracer.ResourceName("CONNECT"))
	defer span.Finish()

	start := time.Now()
	reader := bufio.NewReader(conn)

	reqLine, err := reader.ReadString('\n')
	if err != nil {
		span.SetTag("error", err)
		log.Println("Error reading request:", err)
		return
	}

	if !strings.HasPrefix(reqLine, "CONNECT ") {
		log.Println("Non-CONNECT request ignored:", reqLine)
		span.SetTag("error", "non-CONNECT request")
		return
	}

	parts := strings.Split(reqLine, " ")
	if len(parts) < 2 {
		log.Println("Malformed request:", reqLine)
		span.SetTag("error", "malformed CONNECT line")
		return
	}

	target := parts[1]
	host, _, _ := net.SplitHostPort(target)
	span.SetTag("target.hostport", target)
	span.SetTag("target.hostname", host)

	log.Printf("CONNECT to %s", target)

	// Read HTTP headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	// DNS lookup
	dnsSpan := tracer.StartSpan("dns.lookup", tracer.ChildOf(span.Context()))
	ips, err := net.LookupIP(host)
	dnsSpan.Finish()

	if err != nil || len(ips) == 0 {
		span.SetTag("dns.error", err)
		fmt.Fprint(conn, "HTTP/1.1 502 DNS Lookup Failed\r\n\r\n")
		return
	}
	span.SetTag("target.ip", ips[0].String())

	// Connect to the server
	connSpan := tracer.StartSpan("dial.server", tracer.ChildOf(span.Context()))
	serverConn, err := net.Dial("tcp", target)
	connSpan.Finish()

	if err != nil {
		span.SetTag("error", err)
		log.Printf("Connection error to %s: %v", target, err)
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer serverConn.Close()

	// Confirm the tunnel
	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	log.Printf("Tunnel established for %s in %s", target, time.Since(start))

	// Data transfer
	go io.Copy(serverConn, reader)
	io.Copy(conn, serverConn)
}

func main() {
    tracer.Start(
    tracer.WithAgentAddr("127.0.0.1:8126"),
    tracer.WithServiceName("my-proxy"),
    tracer.WithEnv("dev"),
    tracer.WithDebugMode(true),
 
)

	defer tracer.Stop()

	// Listen on port 8081 instead of 8080
	listener, err := net.Listen("tcp", "127.0.0.1:8081")

	if err != nil {
		log.Fatalf("Proxy startup error: %v", err)
	}
	log.Println("Proxy listening on :8081")

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println("Client accept error:", err)
			continue
		}
		go handleClient(client)
	}
}


