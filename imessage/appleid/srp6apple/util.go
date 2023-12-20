package srp6apple

import (
	"hash"
	"math/big"
)

func padTo(bytes []byte, length int) []byte {
	paddingLength := length - len(bytes)
	padding := make([]byte, paddingLength, paddingLength)

	return append(padding, bytes...)
}

func padToN(number *big.Int, params *SRPParams) []byte {
	return padTo(number.Bytes(), params.Bits/8)
}

func hashToBytes(h hash.Hash) []byte {
	return h.Sum(nil)
}

func hashToInt(h hash.Hash) *big.Int {
	U := new(big.Int)
	U.SetBytes(hashToBytes(h))
	return U
}

func intFromBytes(bytes []byte) *big.Int {
	i := new(big.Int)
	i.SetBytes(bytes)
	return i
}
