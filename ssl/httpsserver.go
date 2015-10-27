package ssl

import (
	"errors"
	// "github.com/ScarletTanager/openssl/crypto"
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	// "sync"
)

func Handle(pattern string, handler http.Handler) {
	http.DefaultServeMux.Handle(pattern, handler)
}

func HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	http.DefaultServeMux.HandleFunc(pattern, handler)
}

type Conn struct {
	net.Conn

	ctx SSL
	f   *os.File
	fd  int
}

func (c Conn) Close() error {
	var e error

	SSL_free(c.ctx)

	if e = c.Conn.Close(); e != nil {
		return e
	}
	if e = c.f.Close(); e != nil {
		return e
	}
	return nil
}

func (c Conn) getHandshake() error {
	if SSL_accept(c.ctx) < 0 {
		return errors.New("SSL handshake unsuccessful")
	}

	return nil
}

func (c Conn) Read(buf []byte) (int, error) {
	result := SSL_read(c.ctx, buf, len(buf))
	if result > 0 {
		return result, nil
	}
	return 0, errors.New("Unable to read from connection.")
}

func (c Conn) Write(buf []byte) (int, error) {
	result := SSL_write(c.ctx, buf, len(buf))
	if result > 0 {
		return result, nil
	}
	return 0, errors.New("Unable to write to connection.")
}

type response struct {
	Conn

	Headers http.Header

	req          *http.Request
	sentStatus   bool
	wroteHeaders bool
}

func (r *response) Close() error {
	if e := r.req.Body.Close(); e != nil {
		return e
	}
	return r.Conn.Close()
}

func (r *response) Header() http.Header {
	return r.Headers
}

func (r *response) Write(buf []byte) (int, error) {
	if !r.sentStatus {
		r.WriteHeader(http.StatusOK)
	}

	if !r.wroteHeaders {
		r.wroteHeaders = true
		r.Headers.Write(r.Conn)
		r.Write([]byte("\r\n"))
	}

	return r.Conn.Write(buf)
}

func (r *response) WriteHeader(s int) {
	r.sentStatus = true
	r.Conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d\r\n", s)))
}

type Server struct {
	Addr    string
	Handler http.Handler

	ctx       SSL_CTX
	listener  net.Listener
	method    SSL_METHOD
	keepalive bool
}

func ListenAndServeTLS(addr, cf, kf string, handler http.Handler) (*Server, error) {
	s := &Server{
		Addr:    addr,
		Handler: handler,
	}

	return s, s.ListenAndServeTLS(cf, kf)
}

func (s *Server) ListenAndServe() error {
	return errors.New("You must use ListenAndServeTLS with this package. It does not support unencrypted HTTP traffic.")
}

func (s *Server) ListenAndServeTLS(cf, kf string) error {
	var (
		e error
	)

	if s.method == nil {
		s.method = SSLv23_server_method()
	}

	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	ctx, e := ctxInit("", s.method)
	if e != nil {
		return e
	}

	if SSL_CTX_use_certificate_file(ctx, cf, SSL_FILETYPE_PEM) <= 0 {
		return errors.New("Could not use certificate file")
	}

	if SSL_CTX_use_PrivateKey_file(ctx, kf, SSL_FILETYPE_PEM) <= 0 {
		return errors.New("Could not use key file")
	}

	if SSL_CTX_check_private_key(ctx) < 1 {
		return errors.New("Private key does not match the public certificate")
	}

	l, e := net.Listen("tcp", s.Addr)
	if e != nil {
		return e
	}

	s.ctx = ctx

	return s.Serve(l)
}

func (s *Server) Serve(l net.Listener) error {
	var (
		c net.Conn
		e error
		f *os.File
	)

	check := func(e error) {
		if e != nil {
			fmt.Printf("ERROR: %s\n", e)
		}
	}

	s.listener = l

	for {
		c, e = s.listener.Accept()
		check(e)

		switch c.(type) {
		case *net.IPConn:
			f, e = c.(*net.IPConn).File()
		case *net.TCPConn:
			f, e = c.(*net.TCPConn).File()
		case *net.UDPConn:
			f, e = c.(*net.UDPConn).File()
		case *net.UnixConn:
			f, e = c.(*net.UnixConn).File()
		}

		check(e)

		c = Conn{
			Conn: c,
			ctx:  SSL_new(s.ctx),
			f:    f,
			fd:   int(f.Fd()),
		}

		oc := c.(Conn)
		SSL_set_fd(oc.ctx, oc.fd)

		check(oc.getHandshake())

		buf := bufio.NewReader(oc)
		req, e := http.ReadRequest(buf)
		check(e)

		res := &response{
			Conn:    oc,
			Headers: make(http.Header),
			req:     req,
		}

		s.Handler.ServeHTTP(res, req)

		check(req.Body.Close())

		check(oc.Close())
	}

	return nil
}

func (s *Server) SetKeepAlivesEnabled(v bool) {
	s.keepalive = v
}
