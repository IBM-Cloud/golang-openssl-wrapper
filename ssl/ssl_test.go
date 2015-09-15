package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ScarletTanager/openssl/crypto"
)

var _ = Describe("ssl", func() {
	Context("Using TLS for connections", func() {
		var ctx SSL_CTX
		// var sslinst SSL
		var host string

		BeforeEach(func() {
			SSL_load_error_strings()
			Expect(SSL_library_init()).To(Equal(1))
			crypto.OPENSSL_config("")
			host = "www.random.org:443"
		})

		AfterEach(func() {
			SSL_CTX_free(ctx)
		})

		Context("Making a client connection", func() {
			It("initializes the context", func() {
				//var ssl *SSL
				ctx = SSL_CTX_new(SSLv23_method())
				Expect(ctx).NotTo(BeNil())
				SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
				SSL_CTX_set_verify_depth(ctx, 4)
	            conn := BIO_new_ssl_connect(ctx)
	            Expect(conn).NotTo(BeNil())
//	            Expect(SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", "")).To(Equal(1))
	            Expect(BIO_set_conn_hostname(conn, host)).To(BeEquivalentTo(1))
				Expect(BIO_get_conn_hostname(conn)).To(Equal(host))
				// sslinst = SSL{}
				// Expect(BIO_get_ssl(conn, sslinst)).To(BeEquivalentTo(1))
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
