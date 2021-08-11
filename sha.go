// package shasum helps to generate digest from stdin string
package shasum

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"os"
)

// SHAsum takes as arguments a number for SHA protocol (256/384/512) and string as input to generate a digest
func SHAsum() {
	sum := flag.Int("s", 256, "sha protocol")
	tod := flag.String("t", "", "string to digest")
	flag.Parse()
	digest, err := getSHAsum(*sum, []byte(*tod))
	if err != nil {
		fmt.Fprint(os.Stderr, err)
	}
	fmt.Fprintln(os.Stdout, digest)
}

func getSHAsum(n int, tod []byte) (string, error) {
	if len(tod) == 0 {
		return "", errors.New("ERROR: Empty string to digest")
	}
	switch n {
	case 256:
		digest := sha256.Sum256(tod)
		return fmt.Sprintf("%x", digest), nil
	case 512:
		digest := sha512.Sum512(tod)
		return fmt.Sprintf("%x", digest), nil
	case 384:
		digest := sha512.Sum384(tod)
		return fmt.Sprintf("%x", digest), nil
	}
	return "", errors.New("ERROR: Not valid protocol number n")
}

func DiffSHA256(d1 [32]byte, d2 [32]byte) int {
	var count int
	for i := range d1 {
		if d1[i] == d2[i] {
			count++
		}
	}
	return count
}
