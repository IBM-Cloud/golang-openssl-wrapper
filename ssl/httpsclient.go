package ssl

/*
 * Module: httpsclient.go
 */

import (
	"errors"
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/bio"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var networksAllowed = map[string]bool{
	"tcp":  true,
	"tcp4": true,
	"tcp6": true,
	"ip":   true,
	"ip4":  true,
	"ip6":  true,
}

// HTTPSConn extends net.Conn to provide HTTPS functions using OpenSSL.
type HTTPSConn struct {
	net.Conn
	desthost   string
	connected  bool
	ctx        SSL_CTX
	sslInst    SSL
	sslBio     bio.BIO
	remoteAddr *net.TCPAddr
	localAddr  *net.TCPAddr
}

// Read reads n bytes from the connection into b.
// Read returns the number of bytes read or 0 and an error if the underlying read fails.
func (h HTTPSConn) Read(b []byte) (n int, err error) {
	ret := bio.BIO_read(h.sslBio, b, len(b))
	if ret < 0 {
		return ret, fmt.Errorf("Possible socket read error - got %d from BIO_read()", ret)
	}
	return ret, nil
}

// Write writes n bytes from b onto the connection.
// Write returns the number of bytes written and any error that occurred.
func (h HTTPSConn) Write(b []byte) (n int, err error) {
	ret := bio.BIO_write(h.sslBio, string(b), len(b))
	if ret != len(b) {
		return ret, fmt.Errorf("SSL socket write failed; only %d bytes written out of %d", ret, len(b))
	}

	return ret, nil
}

// Close closes the underlying connection.
// Close will return an error if it is invoked on a partially or already closed connection.
func (h HTTPSConn) Close() error {
	if (h.ctx != nil) && (h.sslInst != nil) && (h.sslBio != nil) {
		SSL_CTX_free(h.ctx)
		h.ctx = nil
		SSL_free(h.sslInst)
		h.sslInst = nil
		bio.BIO_free_all(h.sslBio)
		h.sslBio = nil
		return nil
	}

	if (h.ctx != nil) || (h.sslInst != nil) || (h.sslBio != nil) {
		return errors.New("HTTPSConn in partially closed state, not all objects freed, unable to close further")
	}

	return errors.New("Attempted to close already closed HTTPSConn")
}

// LocalAddr returns the local address as a net.Addr.
func (h HTTPSConn) LocalAddr() net.Addr {
	return h.localAddr
}

// RemoteAddr returns the remote address for the connection as a net.Addr.
func (h HTTPSConn) RemoteAddr() net.Addr {
	return h.remoteAddr
}

func validateDeadline(t time.Time) error {
	now := time.Now()
	if t.Equal(now) || t.Before(now) {
		return errors.New("Invalid deadline")
	}

	if t.After(now.Add(time.Duration(10) * time.Minute)) {
		return errors.New("Deadline beyond allowed horizon")
	}

	return nil
}

// TODO: implement Set[{Read,Write}]Deadline

// // SetDeadLine sets the deadline for both reads and writes.
// // t should be a time.Time representing a relative interval, such as 10 minutes.
// // SetDeadline, SetReadDeadline, and SetWriteDeadLine will all return an error
// // if t equals the current time or is before it.
// // They will also return an error for an interval longer than 10 minutes.
// func (h HTTPSConn) SetDeadLine(t time.Time) error {
// 	return validateDeadline(t)
// }

// // SetReadDeadLine sets the deadline for reads.
// func (h HTTPSConn) SetReadDeadLine(t time.Time) error {
// 	return validateDeadline(t)
// }

// // SetWriteDeadLine sets the deadline for writes.
// func (h HTTPSConn) SetWriteDeadLine(t time.Time) error {
// 	return validateDeadline(t)
// }

/*
 * Setup the Transport
 */

func dial(network, addr string) (net.Conn, error) {
	return dialTLS(network, addr)
}

/*
 * dialTLS() Returns an httpsclient.HTTPSConn instance.
 * We inject the BIO object for use in I/O.
 * We inject the CTX and SSL objects for use in connection
 * management.
 */
func dialTLS(network, addr string) (net.Conn, error) {
	var err error
	var ctx SSL_CTX
	var conn bio.BIO
	var dest, dhost, dport string
	var ra *net.TCPAddr

	if !networksAllowed[network] {
		return nil, fmt.Errorf("Invalid network specified: %q", network)
	}

	cc := strings.Count(addr, ":")
	switch {
	case cc == 0:
		/* Default is port 443 */
		dhost = addr
		dport = "443"
	case cc == 1:
		dhost, dport, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, errors.New("Unable to parse address")
		}
	case cc > 1:
		return nil, errors.New("Invalid address specified")
	}
	dest = net.JoinHostPort(dhost, dport)

	ra, err = net.ResolveTCPAddr(network, dest)
	if err != nil {
		return nil, fmt.Errorf("Unable to resolve address %s on network %s", dest, network)
	}

	ctx, err = ctxInit("", SSLv23_client_method())
	if err != nil {
		return nil, err
	}

	conn, err = sslInit(ctx, dest)
	if err != nil {
		return nil, err
	}

	err = connect(conn)
	if err != nil {
		return nil, err
	}

	h := HTTPSConn{
		desthost:   addr,
		ctx:        ctx,
		sslBio:     conn,
		remoteAddr: ra,
	}
	return h, nil

}

// NewHTTPSClient returns an http.Client configured to use OpenSSL for TLS.
// The client cannot be used for non-TLS communications - use a regular http.Client instead.
// This is a convenience function wrapping NewHTTPSTransport.
func NewHTTPSClient() http.Client {
	return http.Client{
		Transport: NewHTTPSTransport(nil),
	}
}

// NewHTTPSTransport returns an http.Transport configured to use OpenSSL for TLS.
// The transport cannot be used for non-TLS communications - use a regular http.Transport instead.
func NewHTTPSTransport(proxyFunc func(*http.Request) (*url.URL, error)) *http.Transport {
	h := &http.Transport{
		Dial:    dialTLS,
		DialTLS: dialTLS,
		Proxy:   proxyFunc,
	}
	return h
}

func sslInit(ctx SSL_CTX, hostname string) (bio.BIO, error) {
	/* Initialize the SSL and connect BIOs */
	conn := bio.BIO_new_ssl_connect(ctx)
	if conn == nil {
		return nil, errors.New("Unable to setup I/O")
	}

	if SSL_CTX_load_verify_locations(ctx, "", "/etc/ssl/certs") != 1 {
		return nil, errors.New("Unable to load certificates for verification")
	}
	if bio.BIO_set_conn_hostname(conn, hostname) != 1 {
		return nil, errors.New("Unable to set hostname in BIO object")
	}

	/* Setup SSL */
	sslInst := SSL_new(ctx)
	if sslInst == nil {
		return nil, errors.New("Unable to initialize SSL")
	}

	if bio.BIO_get_ssl(conn, sslInst) != 1 {
		return nil, errors.New("Unable to configure SSL for I/O")
	}

	ciphers := "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"
	if SSL_set_cipher_list(sslInst, ciphers) != 1 {
		return nil, errors.New("Unable to configure ciphers")
	}

	if SSL_set_tlsext_host_name(sslInst, hostname) != 1 {
		return nil, errors.New("Unable to set SSL hostname")
	}

	return conn, nil
}

/* Make the connection */
func connect(conn bio.BIO) error {
	if bio.BIO_do_connect(conn) != 1 {
		return errors.New("Unable to connect to SSL destination")
	}

	if bio.BIO_do_handshake(conn) != 1 {
		return errors.New("Unable to complete SSL handshake")
	}

	return nil
}
