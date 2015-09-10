package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ssl", func() {
	Context("initializing TLS", func() {

		It("initialzes succesfully", func() {
			var ssl *SSL
			Expect(SSL_library_init()).To(Equal(1))
			ctx := SSL_CTX_new(SSLv3_client_method())
			Expect(ctx).NotTo(BeNil())
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
			SSL_CTX_set_verify_depth(ctx, 4)
			flags := SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
            SSL_CTX_set_options(ctx, flags)
            res := SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", nil)
            Expect(res).To(Equal(1)) 
            web := BIO_new_ssl_connect(ctx)
            Expect(web).NotTo(BeNil())
            res := BIO_set_conn_hostname(web, "random-org-chain.pem", 443)
            Expect(res).To(Equal(1))
            BIO_get_ssl(web, &ssl)
            const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MDS:!RC4"
            res := SSL_set_cipher_list(ssl, PREFERRED_CIPHERS)
            Expect(res).To(Equal(1))
            res := SSL_set_t1sext_host_name(ssl, Host_Name)
            Expect(res).To(Equal(1))



			})
		})
/* Cannot fail ??? */


/* Cannot fail ??? */


/* Cannot fail ??? */
//const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
//SSL_CTX_set_options(ctx, flags);
})
