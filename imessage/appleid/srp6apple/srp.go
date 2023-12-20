package srp6apple

import (
	"math/big"
)

func (params *SRPParams) calculateA(a *big.Int) []byte {
	ANum := new(big.Int)
	ANum.Exp(params.G, a, params.N)
	return padToN(ANum, params)
}

func (params *SRPParams) calculateU(A, B *big.Int) *big.Int {
	hashU := params.Hash.New()
	ab := append(padToN(A, params), padToN(B, params)...)
	hashU.Write(ab)
	r := hashToInt(hashU)
	return r
}

func (params *SRPParams) calculateS(k, x, a, B, u *big.Int) []byte {
	BLessThan0 := B.Cmp(big.NewInt(0)) <= 0
	NLessThanB := params.N.Cmp(B) <= 0
	if BLessThan0 || NLessThanB {
		panic("invalid server-supplied 'B', must be 1..N-1")
	}
	result1 := new(big.Int)
	result1.Exp(params.G, x, params.N)

	result2 := new(big.Int)
	result2.Mul(k, result1)

	result3 := new(big.Int)
	result3.Sub(B, result2)

	result4 := new(big.Int)
	result4.Mul(u, x)

	result5 := new(big.Int)
	result5.Add(a, result4)

	result6 := new(big.Int)
	result6.Exp(result3, result5, params.N)

	result7 := new(big.Int)
	result7.Mod(result6, params.N)
	return padToN(result7, params)
}

func (params *SRPParams) calculateK(S []byte) []byte {
	hashK := params.Hash.New()
	hashK.Write(S)
	return hashToBytes(hashK)
}

func (params *SRPParams) calculateX(salt, I, P []byte) *big.Int {
	h := params.Hash.New()
	if !params.NoUserNameInX {
		h.Write(I)
	}
	h.Write([]byte(":"))
	h.Write(P)
	digest := h.Sum(nil)
	h2 := params.Hash.New()

	h2.Write(salt)
	h2.Write(digest)
	x := new(big.Int)
	x.SetBytes(h2.Sum(nil))
	return x
}

func (params *SRPParams) Digest(message []byte) []byte {
	h := params.Hash.New()
	h.Write(message)
	return h.Sum(nil)
}

func (params *SRPParams) calculateM1(username, salt, A, B, K []byte) []byte {
	digestn := params.Digest(padToN(params.G, params))
	digestg := params.Digest(params.N.Bytes())
	digesti := params.Digest(username)
	hxor := make([]byte, len(digestn))
	for i := range digestn {
		hxor[i] = digestn[i] ^ digestg[i]
	}
	h := params.Hash.New()
	h.Write(hxor)
	h.Write(digesti)
	h.Write(salt)
	h.Write(A)
	h.Write(B)
	h.Write(K)
	m1 := h.Sum(nil)
	return m1
}

func (params *SRPParams) calculateM2(A, M1, K []byte) []byte {
	h := params.Hash.New()
	h.Write(A)
	h.Write(M1)
	h.Write(K)
	return h.Sum(nil)
}

func (params *SRPParams) getMultiplier() *big.Int {
	h := params.Hash.New()
	n := params.N.Bytes()
	g := params.G.Bytes()
	for len(g) < len(n) {
		g = append([]byte{0}, g...)
	}
	h.Write(append(n, g...))
	return hashToInt(h)
}
