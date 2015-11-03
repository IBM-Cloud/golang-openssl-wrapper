package rand

import (
	"errors"
)

// Read populates buf with a pseudo-random sequence of bytes read from /dev/random.
// This requires a system with /dev/random.
// Behavior is as for golang's crypto/rand.Read()
func Read(buf []byte) (int, error) {
	l := cap(buf)
	r := RAND_bytes(buf, l)
	if r != 1 {
		return 0, errors.New("Error generating random byte sequence")
	}

	if len(buf) != l {
		return 0, errors.New("Random byte sequence has wrong length")
	}

	return len(buf), nil
}
