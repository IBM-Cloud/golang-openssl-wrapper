package rand

// #cgo CFLAGS: -I/usr/local/ssl/include
// #cgo LDFLAGS: -L /usr/local/ssl/lib -lcrypto
import "C"
