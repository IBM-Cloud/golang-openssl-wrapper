package crypto

// #cgo CFLAGS: -I/usr/local/ssl/include
// #cgo LDFLAGS: -L /usr/local/ssl/lib -lcrypto
import "C"


func FIPSMode(mode ...int) int {

 	// if status, ok := mode[0]; ok {
	if len(mode) > 0 {
  		
  		FIPS_mode_set(mode[0])
  	}
	return FIPS_mode()
	
}


