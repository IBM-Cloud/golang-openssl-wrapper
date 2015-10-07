package digest_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestDigest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Digest Suite")
}
