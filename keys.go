package alexandria

import (
	"io"

	"github.com/minio/blake2b-simd"

	"golang.org/x/crypto/curve25519"
)

func GenerateKey(rand io.Reader) (privateKey *Key, err error) {
	privateKey = (*Key)(new([32]byte))
	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		privateKey = nil
		return
	}
	return
}

type Key [32]byte

func (k *Key) String() string {
	return base58Encode(k[:])
}

func DecodeKey(v string) (key *Key, err error) {
	// TODO validate key
	k := base58Decode(v)
	key = (*Key)(new([32]byte))
	copy(key[:], k)
	return
}

func (privateKey *Key) PublicKey() (publicKey *Key) {
	publicKey = (*Key)(new([32]byte))
	curve25519.ScalarBaseMult((*[32]byte)(publicKey), (*[32]byte)(privateKey))
	return
}

func (privateKey *Key) SharedKey(peersPublicKey *Key) *Key {
	var tmpKey [32]byte
	curve25519.ScalarMult(&tmpKey, (*[32]byte)(privateKey), (*[32]byte)(peersPublicKey))
	sharedKey := blake2b.Sum256(tmpKey[:])
	return (*Key)(&sharedKey)
}
