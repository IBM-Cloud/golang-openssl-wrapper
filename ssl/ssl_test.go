package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ssl", func() {
	Context("initializing TLS", func() {
		It("initialzes succesfully", func() {
			Expect(SSL_library_init()).To(Equal(1))
			ctx := SSL_CTX_new(SSLv3_client_method())
			Expect(ctx).NotTo(BeNil())
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
			SSL_CTX_set_verify_depth(ctx, 4)
			flag := SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
            SSL_CTX_set_options(ctx, flags)

			})
		})
/* Cannot fail ??? */


/* Cannot fail ??? */


/* Cannot fail ??? */
//const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
//SSL_CTX_set_options(ctx, flags);
})
