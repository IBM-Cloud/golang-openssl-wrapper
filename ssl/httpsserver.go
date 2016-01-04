package ssl

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

/*
	Handle is shorthand for:
		http.DefaultServeMux.Handle(pattern, handler)
*/
func Handle(pattern string, handler http.Handler) {
	http.DefaultServeMux.Handle(pattern, handler)
}

/*
	HandleFunc is shorthand for:
		http.DefaultServeMux.Handler(pattern, handler)
*/
func HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	http.DefaultServeMux.HandleFunc(pattern, handler)
}

/*
	Conn is used for incoming server connections.
*/
type Conn struct {
	net.Conn

	ctx SSL
	f   *os.File
	fd  int
}

/*
	Close will free any contexts, files, and connections that are
	associated with the Conn.
*/
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

/*
	Read will use SSL_read to read directly from the file descriptor
	of the open connection.
*/
func (c Conn) Read(buf []byte) (int, error) {
	result := SSL_read(c.ctx, buf, len(buf))
	if result > 0 {
		return result, nil
	}
	return 0, errors.New("Unable to read from connection.")
}

/*
	Write will use SSL_write to write directly to the file descriptor
	of the open connection.
*/
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
	r.Conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n", s, http.StatusText(s))))
}

/*
	Server mimics the original http.Server. It provides the same methods
	as the original http.Server to be a drop-in replacement.
*/
type Server struct {
	Addr     string
	Handler  http.Handler
	ErrorLog *log.Logger

	ctx       SSL_CTX
	listener  net.Listener
	method    SSL_METHOD
	keepalive bool
}

/*
	ListenAndServeTLS will create a new Server and call ListenAndServeTLS
	on the Server instance.

	cf should be an absolute or relative path to the certificate file.
	kf should be an absolute or relative path to the key file.
*/
func ListenAndServeTLS(addr, cf, kf string, handler http.Handler) (*Server, error) {
	s := &Server{
		Addr:    addr,
		Handler: handler,
	}

	return s, s.ListenAndServeTLS(cf, kf)
}

/*
	ListenAndServe is not supported by this package and will always return
	a hardcoded error saying so. We do not support unencrypted traffic in
	this module.
*/
func (s *Server) ListenAndServe() error {
	return errors.New("You must use ListenAndServeTLS with this package. It does not support unencrypted HTTP traffic.")
}

/*
	ListenAndServeTLS will setup default values, contexts, the certificate,
	and key file. It will then listen on the Addr set in the Server instance and
	call Server.Serve.

	cf should be an absolute or relative path to the certificate file.
	kf should be an absolute or relative path to the key file.
*/
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

	if s.ErrorLog == nil {
		s.ErrorLog = log.New(os.Stdout, "server: ", log.LstdFlags|log.Lshortfile)
	}

	cf, e = filepath.Abs(cf)
	if e != nil {
		return e
	}

	kf, e = filepath.Abs(kf)
	if e != nil {
		return e
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

/*
	Serve will accept connections on the net.Listener provided. It will then call
	Server.Handler.ServeHTTP on the resulting connection.

	You should not close the connection in Server.Handler.ServeHTTP. The
	connection will be automatically closed once Server.Handler.ServeHTTP
	has finished.
*/
func (s *Server) Serve(l net.Listener) error {
	var (
		c net.Conn
		e error
		f *os.File
	)

	check := func(e error) {
		if e != nil {
			s.ErrorLog.Printf("ERROR: %s\n", e)
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
