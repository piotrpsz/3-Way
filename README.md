# 3-Way
3-Way algorithm implemented in Go

3-Way is a block cipher designed by Joan Daemen. It has 96-bit block length and key length.
Algorithm works in n rounds. Daemen recommends 11.<br>
<b>So far, there has been no successful cryptoanalysis of 3-Way.</b><br>
The algorithm is unpatented.

# Example: How to test
The test file called 'threeway_test.go' is in repository.<br>
<b>For test run command: go test -v</b><br>
Test vectors are from implementation of 3-Way in book "Applied Cryptography" - author Bruce Schneier.

```Go
// for test run command: go test -v

package threeway

import (
	"fmt"
	"testing"
)

func vectorString(text string, a []uint32) string {
	return fmt.Sprintf("%20s : %08x, %08x, %08x", text, a[2], a[1], a[0])
}

func Test_1(t *testing.T) {	
	tw := New()
	tw.KeyGenerator(0, 0, 0)
	a0, a1, a2 := uint32(1), uint32(1), uint32(1) // plain text
	e0, e1, e2 := uint32(0x4059c76e), uint32(0x83ae9dc4), uint32(0xad21ecf7) // expected cipher text
	c0, c1, c2 := tw.EncryptBlock(a0, a1, a2) // cipher text
	r0, r1, r2 := tw.DecryptBlock(c0, c1, c2) // plain text again

	fmt.Println("**********************************************************************")
	fmt.Println(vectorString("key", tw.k[:]))
	fmt.Println(vectorString("plain", []uint32{a0, a1, a2}))
	fmt.Println(vectorString("cipher", []uint32{c0, c1, c2}))
	fmt.Println(vectorString("result", []uint32{r0, r1, r2}))
	if (c0 != e0) || (c1 != e1) || (c2 != e2) {
		t.Errorf("Invalid encryption.\n%s\n", vectorString("should be", []uint32{e0, e1, e2}))
	}
}

func Test_2(t *testing.T) {	
	tw := New()
	tw.KeyGenerator(6, 5, 4)
	a0, a1, a2 := uint32(3), uint32(2), uint32(1) // plain text
	e0, e1, e2 := uint32(0xd2f05b5e), uint32(0xd6144138), uint32(0xcab920cd) // expected cipher text
	c0, c1, c2 := tw.EncryptBlock(a0, a1, a2) // cipher text
	r0, r1, r2 := tw.DecryptBlock(c0, c1, c2) // plain text again

	fmt.Println("**********************************************************************")
	fmt.Println(vectorString("key", tw.k[:]))
	fmt.Println(vectorString("plain", []uint32{a0, a1, a2}))
	fmt.Println(vectorString("cipher", []uint32{c0, c1, c2}))
	fmt.Println(vectorString("result", []uint32{r0, r1, r2}))
	if (c0 != e0) || (c1 != e1) || (c2 != e2) {
		t.Errorf("Invalid encryption.\n%s\n", vectorString("should be", []uint32{e0, e1, e2}))
	}
}

func Test_3(t *testing.T) {	
	tw := New()
	tw.KeyGenerator(0xdef01234, 0x456789ab, 0xbcdef012)
	a0, a1, a2 := uint32(0x23456789), uint32(0x9abcdef0), uint32(0x01234567) // plain text
	e0, e1, e2 := uint32(0x0aa55dbb), uint32(0x9cdddb6d), uint32(0x7cdb76b2) // expected cipher text
	c0, c1, c2 := tw.EncryptBlock(a0, a1, a2) // cipher text
	r0, r1, r2 := tw.DecryptBlock(c0, c1, c2) // plain text again

	fmt.Println("**********************************************************************")
	fmt.Println(vectorString("key", tw.k[:]))
	fmt.Println(vectorString("plain", []uint32{a0, a1, a2}))
	fmt.Println(vectorString("cipher", []uint32{c0, c1, c2}))
	fmt.Println(vectorString("result", []uint32{r0, r1, r2}))
	if (c0 != e0) || (c1 != e1) || (c2 != e2) {
		t.Errorf("Invalid encryption.\n%s\n", vectorString("should be", []uint32{e0, e1, e2}))
	}
}

func Test_4(t *testing.T) {	
	tw := New()
	tw.KeyGenerator(0xd2f05b5e, 0xd6144138, 0xcab920cd)
	a0, a1, a2 := uint32(0x4059c76e), uint32(0x83ae9dc4), uint32(0xad21ecf7) // plain text
	e0, e1, e2 := uint32(0x478ea871), uint32(0x6b13f17c), uint32(0x15b155ed) // expected cipher text
	c0, c1, c2 := tw.EncryptBlock(a0, a1, a2) // cipher text
	r0, r1, r2 := tw.DecryptBlock(c0, c1, c2) // plain text again

	fmt.Println("**********************************************************************")
	fmt.Println(vectorString("key", tw.k[:]))
	fmt.Println(vectorString("plain", []uint32{a0, a1, a2}))
	fmt.Println(vectorString("cipher", []uint32{c0, c1, c2}))
	fmt.Println(vectorString("result", []uint32{r0, r1, r2}))
	if (c0 != e0) || (c1 != e1) || (c2 != e2) {
		t.Errorf("Invalid encryption.\n%s\n", vectorString("should be", []uint32{e0, e1, e2}))
	}
}

```
