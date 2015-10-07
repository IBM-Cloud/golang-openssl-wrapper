package digest_test

import (
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
})
