package x509_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestX509(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "X509 Suite")
}
