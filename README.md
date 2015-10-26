# golang-openssl-wrapper

OpenSSL wrapper for go

To use:

    import "github.com/IBM-Bluemix/golang-openssl-wrapper/crypto" // For encryption, e.g. EVP
    import "github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"    // TLS
    import "github.com/IBM-Bluemix/golang-openssl-wrapper/rand"   // PRNG
    import "github.com/IBM-Bluemix/golang-openssl-wrapper/digest" // Message-digest (hash) functions
    import "github.com/IBM-Bluemix/golang-openssl-wrapper/bio"    // OpenSSL-specific I/O handling
    
This library is being actively developed.  It provides access to much of the OpenSSL APIs for cryptography (libcrypto) and TLS (libssl).  We do not plan to provide the complete API at first, but if there is a function you need, please open an issue or submit a PR.  The wrapper is built on `swig`, so you will need to work directly with the `.swig` files to add functionality.

If you submit a pull request, please be sure to include complete unit test coverage (we use `ginkgo` and `gomega`, which sit on top of golang's native testing facility), or your PR will be declined.
