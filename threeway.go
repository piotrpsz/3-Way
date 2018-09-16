/*
	threeway.go:  3-Way algorithm implementation in Go.

	Copyright (C) 2018 by Piotr Pszczółkowski (piotr@beesoft.pl)

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	If you require this code under a license other than LGPL, please ask.
*/
package threeway

// block size := 3 x uint32, 12 bytes, 96 bits
// key size := 3 x uint32, 12 bytes, 96 bits
// rounds := 11

const (
	nmbr  = 11	// number of rounds
)

var (
	// array which contains the round constants for the encryption rounds
	ercon = [12]uint32 {0x0b0b, 0x1616, 0x2c2c, 0x5858, 0xb0b0, 0x7171, 0xe2e2, 0xd5d5, 0xbbbb, 0x6767, 0xcece, 0x8d8d}
	// array which contains the round constants for the decryption rounds
	drcon = [12]uint32 {0xb1b1, 0x7373, 0xe6e6, 0xdddd, 0xabab, 0x4747, 0x8e8e, 0x0d0d, 0x1a1a, 0x3434, 0x6868, 0xd0d0}
)

type ThreeWay struct {
	k  [3]uint32
	ki [3]uint32
}

func New() *ThreeWay {
	tw := new(ThreeWay)
	return tw
}

func (tw *ThreeWay) KeyGenerator(k0, k1, k2 uint32) {
	tw.k[0] = k0
	tw.k[1] = k1
	tw.k[2] = k2

	tw.ki[0], tw.ki[1], tw.ki[2] = mu(theta(k0, k1, k2))
}

func mu(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	w0, w1, w2 := uint32(0), uint32(0), uint32(0)

	for i := 0; i < 32; i++ {
		w0 <<= 1;
		w1 <<= 1;
		w2 <<= 1;

		if (a0 & 1) > 0 {
			w2 |= 1;
		}
		if (a1 & 1) > 0 {
			w1 |= 1;
		}
		if (a2 & 1) > 0 {
			w0 |= 1;
		}
		
		a0 >>= 1;
		a1 >>= 1;
		a2 >>= 1;
	}
	return w0, w1, w2
}

func gamma(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	w0 := (^a0) ^ ((^a1) & a2);
	w1 := (^a1) ^ ((^a2) & a0);
	w2 := (^a2) ^ ((^a0) & a1);

	return w0, w1, w2
}

func theta(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	w0 := a0 ^
		(a0 >> 16) ^ (a1 << 16) ^
		(a1 >> 16) ^ (a2 << 16) ^
		(a1 >> 24) ^ (a2 <<  8) ^
		(a2 >>  8) ^ (a0 << 24) ^
		(a2 >> 16) ^ (a0 << 16) ^
		(a2 >> 24) ^ (a0 <<  8);

	w1 := a1 ^
		(a1 >> 16) ^ (a2 << 16) ^
		(a2 >> 16) ^ (a0 << 16) ^
		(a2 >> 24) ^ (a0 <<  8) ^
		(a0 >>  8) ^ (a1 << 24) ^
		(a0 >> 16) ^ (a1 << 16) ^
		(a0 >> 24) ^ (a1 <<  8);

	w2 := a2 ^
		(a2 >> 16) ^ (a0 << 16) ^
		(a0 >> 16) ^ (a1 << 16) ^
		(a0 >> 24) ^ (a1 <<  8) ^
		(a1 >>  8) ^ (a2 << 24) ^
		(a1 >> 16) ^ (a2 << 16) ^
		(a1 >> 24) ^ (a2 <<  8);

	return w0, w1, w2
}
func pi_1(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	w0 := (a0 >> 10) ^ (a0 << 22)
	w1 := a1
	w2 := (a2 <<  1) ^ (a2 >> 31)
	
	return w0, w1, w2
}

func pi_2(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	w0 := (a0 <<  1) ^ (a0 >> 31)
	w1 := a1
	w2 := (a2 >> 10) ^ (a2 << 22)

	return w0, w1, w2
}

func rho(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	return pi_2(gamma(pi_1(theta(a0, a1, a2))))
}

func (tw *ThreeWay) EncryptBlock(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	for i := 0; i < nmbr; i++ {
		a0 ^= (tw.k[0] ^ (ercon[i] << 16))
		a1 ^= tw.k[1]
		a2 ^= (tw.k[2] ^ ercon[i])
		a0, a1, a2 = rho(a0, a1, a2)
	}
	a0 ^= (tw.k[0] ^ (ercon[nmbr] << 16))
	a1 ^= tw.k[1]
	a2 ^= (tw.k[2] ^ ercon[nmbr])

	return theta(a0, a1, a2)
}

func (tw *ThreeWay) DecryptBlock(a0, a1, a2 uint32) (uint32, uint32, uint32) {
	a0, a1, a2 = mu(a0, a1, a2)

	for i := 0; i < nmbr; i++ {
		a0 ^= (tw.ki[0] ^ (drcon[i] << 16))
		a1 ^= tw.ki[1]
		a2 ^= (tw.ki[2] ^ drcon[i])
		a0, a1, a2 = rho(a0, a1, a2)
	}	
	a0 ^= (tw.ki[0] ^ (drcon[nmbr] << 16))
	a1 ^= tw.ki[1]
	a2 ^= (tw.ki[2] ^ drcon[nmbr])

	return mu(theta(a0, a1, a2))
}
