package digest_test

import (
	"github.com/ScarletTanager/openssl/crypto"
	. "github.com/ScarletTanager/openssl/digest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Digest", func() {
	Context("Creating and destroying a context", func() {
		It("Creates and destroys using the built-in (de)allocation mechanism", func() {
			ctx := EVP_MD_CTX_create()
			Expect(ctx).NotTo(BeNil())
			EVP_MD_CTX_init(ctx)
			EVP_MD_CTX_destroy(ctx)
		})

		It("Creates and destroys using user-controlled (de)allocation", func() {
			ctx := Malloc_EVP_MD_CTX()
			Expect(ctx).NotTo(BeNil())
			EVP_MD_CTX_init(ctx)
			Expect(EVP_MD_CTX_cleanup(ctx)).To(Equal(1))
			Free_EVP_MD_CTX(ctx)
		})
	})

	Context("Hashing binary data", func() {
		Context("With FIPS mode enabled", func() {
			var ctx EVP_MD_CTX

			BeforeEach(func() {
				crypto.FIPS_mode_set(1)
				Expect(crypto.FIPS_mode()).To(Equal(1))
				ctx = Malloc_EVP_MD_CTX()
				Expect(ctx).NotTo(BeNil())
				EVP_MD_CTX_init(ctx)
			})

			AfterEach(func() {
				crypto.FIPS_mode_set(0)
				Expect(crypto.FIPS_mode()).To(Equal(0))
			})

			It("Allows use of SHA* but disallows MD5", func() {
				Expect(EVP_DigestInit_ex(ctx, EVP_md5(), SwigcptrStruct_SS_engine_st(0))).To(Equal(0))
				Expect(EVP_DigestInit_ex(ctx, EVP_sha256(), SwigcptrStruct_SS_engine_st(0))).To(Equal(1))
			})
		})
	})
})
