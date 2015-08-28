package openssl_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestOpenssl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Openssl Suite")
}
