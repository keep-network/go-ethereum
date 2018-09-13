// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// +build amd64 arm64

// Package bn256 implements the Optimal Ate pairing over a 256-bit Barreto-Naehrig curve.
package bn256

import (
	"math/big"

	"github.com/herumi/mcl/ffi/go/mcl"
)

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 struct {
	g1 mcl.G1
}

func (g *G1) Marshal() []byte {
	return g.g1.Serialize()
}

func (g *G1) Unmarshal(bytes []byte) (*G1, error) {
	return g, g.g1.Deserialize(bytes)
}

func (g *G1) Add(a, b *G1) *G1 {
	mcl.G1Add(&g.g1, &a.g1, &b.g1)
	return g
}

func (g *G1) ScalarMult(a *G1, k *big.Int) *G1 {
	fr := &mcl.Fr{}
	fr.SetString(k.String(), 10)

	mcl.G1Mul(&g.g1, &a.g1, fr)
	return g
}

// G2 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G2 struct {
	g2 mcl.G2
}

func (g *G2) Marshal() []byte {
	return g.g2.Serialize()
}

func (g *G2) Unmarshal(bytes []byte) (*G2, error) {
	return g, g.g2.Deserialize(bytes)
}

// gfP12 implements the field of size p¹² as a quadratic extension of gfP6
// where ω²=τ.
/*type gfP12 struct {
	x, y gfP6 // value is xω + y
}

func pairingCheck(a []*G1, b []*G2) bool {
	acc := new(gfP12)
	acc.SetOne()

	for i := 0; i < len(a); i++ {
		if a[i].p.IsInfinity() || b[i].p.IsInfinity() {
			continue
		}
		acc.Mul(acc, miller(b[i].p, a[i].p))
	}
	return finalExponentiation(acc).IsOne()
}*/

func init() {
	mcl.Init(mcl.CurveSNARK1)
}

// PairingCheck calculates the Optimal Ate pairing for a set of points.
func PairingCheck(a []*G1, b []*G2) bool {
	// bn256.gfP12 -> mcl.GT
	// acc.SetOne()
	acc := mcl.GT{}
	acc.SetInt64(1)

	for i := 0; i < len(a); i++ {
		gt := mcl.GT{}
		mcl.MillerLoop(&gt, &a[i].g1, &b[i].g2)
		mcl.GTMul(&acc, &acc, &gt)
	}

	ret := mcl.GT{}
	mcl.FinalExp(&ret, &acc)

	return ret.IsOne()
}
