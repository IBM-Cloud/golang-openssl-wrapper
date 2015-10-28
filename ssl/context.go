package ssl

import (
	"errors"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
)

func ctxInit(config string, method SSL_METHOD) (SSL_CTX, error) {
	SSL_load_error_strings()
	if SSL_library_init() != 1 {
		return nil, errors.New("Unable to initialize libssl")
	}
	crypto.OPENSSL_config(config)

	ctx := SSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("Unable to initialize SSL context")
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
	SSL_CTX_set_verify_depth(ctx, 4)

	return ctx, nil
}
