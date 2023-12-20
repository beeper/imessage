package srp6apple

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math/big"

	"go.mau.fi/util/random"
	"golang.org/x/crypto/pbkdf2"
)

type SRPClient struct {
	Params     *SRPParams
	Secret1    *big.Int
	Multiplier *big.Int
	A          *big.Int
	X          *big.Int
	M1         []byte
	M2         []byte
	K          []byte
	u          *big.Int
	s          *big.Int
}

func New() *SRPClient {
	param := defaultParams2048
	a := random.Bytes(32)
	multiplier := param.getMultiplier()
	secret1Int := intFromBytes(a)
	Ab := param.calculateA(secret1Int)
	A := intFromBytes(Ab)
	return &SRPClient{
		Params:     param,
		Multiplier: multiplier,
		Secret1:    secret1Int,
		A:          A,
	}
}

const (
	ProtocolS2KFO = "s2k_fo"
	ProtocolS2K   = "s2k"
)

func (c *SRPClient) Compute(username, password, protocol string, iterationCount int, salt, b []byte) {
	key := srpPassword(sha256.New, protocol == ProtocolS2KFO, []byte(password), salt, iterationCount)
	c.processClientChallenge([]byte(username), key, salt, b)
}

func (c *SRPClient) ABytes() []byte {
	return padToN(c.A, c.Params)
}

func srpPassword(h func() hash.Hash, s2kfo bool, password []byte, salt []byte, iterationCount int) []byte {
	hashPass := sha256.New()
	hashPass.Write(password)
	var digest []byte
	if s2kfo {
		digest = []byte(hex.EncodeToString(hashPass.Sum(nil)))
	} else {
		digest = hashPass.Sum(nil)
	}
	return pbkdf2.Key(digest, salt, iterationCount, h().Size(), h)
}

func (c *SRPClient) processClientChallenge(username, password, salt, B []byte) {
	c.X = c.Params.calculateX(salt, username, password)
	bigB := intFromBytes(B)
	u := c.Params.calculateU(c.A, bigB)
	k := c.Multiplier
	S := c.Params.calculateS(k, c.X, c.Secret1, bigB, u)
	c.K = c.Params.calculateK(S)
	c.u = u
	c.s = intFromBytes(S)
	A := padToN(c.A, c.Params)
	c.M1 = c.Params.calculateM1(username, salt, A, B, c.K)
	c.M2 = c.Params.calculateM2(A, c.M1, c.K)
}
