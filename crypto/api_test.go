package crypto_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Api", func() {

	Context("Enabling and disabling FIPS mode with API", func() {
		BeforeEach(func() {
			FIPS_mode_set(0)
			Expect(FIPS_mode()).To(Equal(0))
		})

		It("should return the current setting", func() {
			Expect(FIPSMode(1)).To(Equal(1))
			Expect(FIPS_mode()).To(Equal(1))
		})

		It("should return disabled FIPS mode", func() {
			Expect(FIPSMode(0)).To(Equal(0))
			Expect(FIPS_mode()).To(Equal(0))
		})

		AfterEach(func() {
			FIPSMode(0)
		})
	})
})
