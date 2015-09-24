package ssl

/*
 * Module: httpsconn
 */

import (
	"errors"
	"fmt"
	"github.com/ScarletTanager/openssl/bio"
	"github.com/ScarletTanager/openssl/crypto"
	"net"
	"net/http"
	"net/url"
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

/*
 * Implements net.Conn
 */
type HttpsConn struct {
	net.Conn
	desthost  string
	connected bool
	ctx       SSL_CTX
	sslInst   SSL
	sslBio    bio.BIO
}

func (h HttpsConn) Read(b []byte) (n int, err error) {

	return 0, nil
}

func (h HttpsConn) Write(b []byte) (n int, err error) {

	return 0, nil
}

func (h HttpsConn) Close() error {

	return nil
}

func (h HttpsConn) LocalAddr() net.Addr {

	return nil
}

func (h HttpsConn) RemoteAddr() net.Addr {

	return nil
}

func (h HttpsConn) SetDeadLine(t time.Time) error {
	now := time.Now()
	if t.Equal(now) || t.Before(now) {
		return errors.New("Invalid deadline")
	}

	return nil
}

func (h HttpsConn) SetReadDeadLine(t time.Time) error {
	now := time.Now()
	if t.Equal(now) || t.Before(now) {
		return errors.New("Invalid deadline")
	}

	return nil
}

func (h HttpsConn) SetWriteDeadLine(t time.Time) error {
	now := time.Now()
	if t.Equal(now) || t.Before(now) {
		return errors.New("Invalid deadline")
	}

	return nil
}

/*
 * Setup the Transport
 */

func dial(network, addr string) (net.Conn, error) {
	return dialTLS(network, addr)
}

/*
 * dialTLS() Returns an httpsclient.HttpsConn instance.
 * We inject the BIO object for use in I/O.
 * We inject the CTX and SSL objects for use in connection
 * management.
 */
func dialTLS(network, addr string) (net.Conn, error) {
	var err error
	var ctx SSL_CTX
	var conn bio.BIO

	if !networksAllowed[network] {
		return nil, fmt.Errorf("Invalid network specified: %q", network)
	}

	ctx, err = ctxInit("")
	if err != nil {
		return nil, err
	}

	conn, err = sslInit(ctx, addr)
	if err != nil {
		return nil, err
	}

	err = connect(conn)
	if err != nil {
		return nil, err
	}

	h := HttpsConn{
		desthost: addr,
		ctx:      ctx,
		sslBio:   conn,
	}
	return h, nil

}

func NewHttpsTransport(proxyFunc func(*http.Request) (*url.URL, error)) http.Transport {
	h := http.Transport{
		Dial:    dialTLS,
		DialTLS: dialTLS,
		Proxy:   proxyFunc,
	}
	return h
}

func ctxInit(config string) (SSL_CTX, error) {
	SSL_load_error_strings()
	if SSL_library_init() != 1 {
		return nil, errors.New("Unable to initialize libssl")
	}
	crypto.OPENSSL_config(config)

	ctx := SSL_CTX_new(SSLv23_client_method())
	if ctx == nil {
		return nil, errors.New("Unable to initialize SSL context")
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
	SSL_CTX_set_verify_depth(ctx, 4)

	return ctx, nil
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
