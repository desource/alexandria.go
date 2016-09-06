package alex

import (
	"io"

	"desource.net/alex/base58"
	blake2b "github.com/minio/blake2b-simd"
	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey Generates a private key
// Returns an error if not enough entorpy
func GeneratePrivateKey(rand io.Reader) (key PrivateKey, err error) {
	var n int
	n, err = io.ReadFull(rand, key[:])
	if err == nil && n != len(key) {
		err = ErrInsufficientEntropy
	}
	return
}

type PrivateKey [32]byte

func (k PrivateKey) String() string {
	return base58.Encode(k[:])
}

func DecodePrivateKey(v string) (key PrivateKey, err error) {
	if v == "" {
		return key, ErrEmptyKey
	}
	k := base58.Decode(v) // TODO improve key validation
	copy(key[:], k)
	return
}

func (privateKey PrivateKey) PublicKey() (publicKey PublicKey) {
	curve25519.ScalarBaseMult((*[32]byte)(&publicKey), (*[32]byte)(&privateKey))
	return
}

func (privateKey PrivateKey) sharedKey(peersPublicKey *PublicKey) sharedKey {
	var tmpKey [32]byte
	curve25519.ScalarMult(&tmpKey, (*[32]byte)(&privateKey), (*[32]byte)(peersPublicKey))
	key := blake2b.Sum256(tmpKey[:])
	return (sharedKey)(key)
}

type PublicKey [32]byte

func DecodePublicKey(v string) (key PublicKey, err error) {
	if v == "" {
		return key, ErrEmptyKey
	}
	k := base58.Decode(v) // TODO validate key
	copy(key[:], k)
	return
}

func (k PublicKey) String() string {
	return base58.Encode(k[:])
}

type sharedKey [32]byte
