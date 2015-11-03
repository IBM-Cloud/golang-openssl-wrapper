package x509_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/x509"

	"github.com/IBM-Bluemix/golang-openssl-wrapper/bio"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = XDescribe("X509", func() {
	var x X509
	It("Should create a new X509 instance", func() {
		x = X509_new()
		Expect(x).NotTo(BeNil())
	})

	It("Should free the X509 instance", func() {
		X509_free(x)
	})

	Context("Reading PEM data from a memory BIO", func() {
		It("Should read with nil X509 and return new X509", func() {
			b := bio.BIO_new(bio.BIO_s_mem())
			cert := CERTS["google"]
			x = nil
			Expect(bio.BIO_write(b, cert, len(cert))).To(Equal(len(cert)))
			result := PEM_read_bio_X509(b, &x, nil, "")
			Expect(result).NotTo(BeNil())
			Expect(result).NotTo(BeEquivalentTo(0))
			X509_free(result)
			bio.BIO_free(b)
		})

		It("Should read with existing X509 and return new X509", func() {
			Skip("This test may contain a known OpenSSL bug")
			b := bio.BIO_new(bio.BIO_s_mem())
			cert := CERTS["google"]
			x = X509_new()
			Expect(bio.BIO_write(b, cert, len(cert))).To(Equal(len(cert)))
			// result := PEM_read_bio_X509(b, &x, nil, "")
			Expect(PEM_read_bio_X509(b, &x, nil, "")).To(BeEquivalentTo(0))
			// Expect(result).NotTo(BeNil())
			// Expect(result).NotTo(BeEquivalentTo(0))
			// X509_free(result)
			X509_free(x)
			bio.BIO_free(b)
		})
	})

	Context("Reading PEM data from a file BIO", func() {
		It("Should read with nil X509 and return new X509", func() {
			b := bio.BIO_new(bio.BIO_s_file())
			Expect(bio.BIO_read_filename(b, CERTFILES["google"])).To(Equal(1))
			x = nil
			result := PEM_read_bio_X509(b, &x, nil, "")
			Expect(result).NotTo(BeNil())
			Expect(result).NotTo(BeEquivalentTo(0))
			X509_free(result)
			bio.BIO_free(b)
		})
	})
})
