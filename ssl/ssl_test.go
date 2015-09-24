package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	"github.com/ScarletTanager/openssl/bio"
	"github.com/ScarletTanager/openssl/crypto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ssl", func() {
	Context("Using TLS for connections", func() {
		var ctx SSL_CTX
		var ssl SSL
		var conn bio.BIO
		var host, hostport string

		BeforeEach(func() {
			SSL_load_error_strings()
			Expect(SSL_library_init()).To(Equal(1))
			crypto.OPENSSL_config("")
			host = "www.random.org"
			hostport = "www.random.org:443"
		})

		AfterEach(func() {
			SSL_free(ssl)
			SSL_CTX_free(ctx)
		})

		Context("Making a client connection", func() {
			It("initializes the context", func() {
				type foo struct {
					name string
					age  int
				}
				ctx = SSL_CTX_new(SSLv23_method())
				Expect(ctx).NotTo(BeNil())
				SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
				SSL_CTX_set_verify_depth(ctx, 4)

				/* Initialize the SSL and connect BIOs */
				conn = bio.BIO_new_ssl_connect(ctx)
				Expect(conn).NotTo(BeNil())
				Expect(SSL_CTX_load_verify_locations(ctx, "", "/etc/ssl/certs")).To(Equal(1))
				Expect(bio.BIO_set_conn_hostname(conn, hostport)).To(BeEquivalentTo(1))
				Expect(bio.BIO_get_conn_hostname(conn)).To(Equal(hostport))

				/* Setup SSL */
				ssl = SSL_new(ctx)
				Expect(ssl).NotTo(BeNil())
				Expect(bio.BIO_get_ssl(conn, ssl)).To(BeEquivalentTo(1))
				ciphers := "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"
				Expect(SSL_set_cipher_list(ssl, ciphers)).To(Equal(1))
				Expect(SSL_set_tlsext_host_name(ssl, host)).To(BeEquivalentTo(1))
			})

			It("Connects successfully", func() {
				/* Make the connection */
				Expect(bio.BIO_do_connect(conn)).To(BeEquivalentTo(1))
				// Expect(crypto.BIO_do_handshake(conn.(crypto.BIO))).To(BeEquivalentTo(1))
			})
			/*flags := SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
			  SSL_CTX_set_options(ctx, flags)
			  Expect(host).To(Equal(1))
			  //port := BIO_set_conn_port(web, 443)
			  BIO_get_ssl(web, &ssl)
			  const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MDS:!RC4"
			  cipher := SSL_set_cipher_list(ssl, PREFERRED_CIPHERS)
			  Expect(cipher).To(Equal(1)) */
		})
	})
	/* Cannot fail ??? */

	/* Cannot fail ??? */

	/* Cannot fail ??? */
	//const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	//SSL_CTX_set_options(ctx, flags);
})
