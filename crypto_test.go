package crypto_test

import (
	. "github.com/ScarletTanager/openssl/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto", func() {

	Describe("Using FIPS mode", func() {
		Context("Enabling and disabling FIPS mode", func() {
			It("should return the current setting", func() {
				FIPS_mode_set(1)
				Expect(FIPS_mode()).To(Equal(1))
				FIPS_mode_set(0)
				Expect(FIPS_mode()).To(Equal(0))
			})
		})
	})
})
