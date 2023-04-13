package sm4

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/cpu"
)

//go:noescape
func TestAsm(a, b int) int

// //go:noescape
// func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

// //go:noescape
// func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

var supportsSMID = cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasAES

func newCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	if !supportsSMID {
		return newCipherGeneric(key)
	}
	c := new(Sm4Cipher)
	c.subkeys = generateSubKeys(key)
	c.block1 = make([]uint32, 4)
	c.block2 = make([]byte, 16)

	return c, nil
}

func TestSm4Asm() {
	var fireFox int
	var edge int
	fireFox = 18
	edge = 22
	if supportsSMID {
		res := TestAsm(fireFox, edge)
		fmt.Println("fireFox = ", fireFox, " edge = ", edge, "result = ", res)
	}

}
