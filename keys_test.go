package alex

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	var zeroed [32]byte

	if reflect.DeepEqual(privateKey, zeroed[:]) {
		t.Error("private key should not be zeroed")
	}

	publicKey := privateKey.PublicKey()
	if reflect.DeepEqual(publicKey, zeroed[:]) {
		t.Error("public keys should not be zeroed")
	}
	if !reflect.DeepEqual(publicKey, privateKey.PublicKey()) {
		t.Error("public keys should not be zeroed")
	}

	if len(privateKey.String()) == 0 {
		t.Error("Expected private key to not be empty")
	}
	t.Logf("Generated Keys\nPublic:  %s\nPrivate: %s", publicKey, privateKey)

}

func TestDecodeKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	v := privateKey.String()

	decodedKey, err := DecodePrivateKey(v)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(privateKey[:], decodedKey[:]) {
		t.Error("Expected pubicKey\n '%s'\nto equal\n '%s'", privateKey.String(), decodedKey.String())
	}
}

func TestSharedKey(t *testing.T) {
	privateKey1, err := GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	privateKey2, err := GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	publicKey2 := privateKey2.PublicKey()

	shared := privateKey1.sharedKey(&publicKey2)

	t.Logf("Generated shared key %s", shared)
}
