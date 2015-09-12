package crypto

// #cgo CFLAGS: -I/usr/local/ssl/include -O0
// #cgo LDFLAGS: -L /usr/local/ssl/lib -lcrypto
import "C"
