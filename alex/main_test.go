package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"desource.net/alex"
)

func TestGeneratePrivateKeys(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := GenKey(&out)
	if err != nil {
		t.Errorf("Failed to GenKey %s", err)
	}
	key1 := out.String()
	t.Logf("Private key1 %s", key1)

	if len(key1) == 0 {
		t.Error("key1 is empty")
	}

	out.Reset()

	err = GenKey(&out)
	if err != nil {
		t.Errorf("Failed to GenKey %s", err)
	}
	key2 := out.String()
	t.Logf("Private key2 %s", key2)
	if len(key2) == 0 {
		t.Error("key2 is empty")
	}

	if key1 == key2 {
		t.Error("two GenKey's should not be equal")
	}
}

var (
	examplePrivateKey = "Cw9S8tyzkzmyoKiRcx2E1JfhBKe93NbihtADv7DQbMzf"
	examplePublicKey  = "Aepn9RuXBjeggcUtMDbzycXoT7ZdpezmzT379BNY8ENs"
	exampleMsg        = "Hello World"
)

func TestPublicKeyFromPrivate(t *testing.T) {
	t.Parallel()

	in := bytes.NewBufferString(examplePrivateKey)
	var out bytes.Buffer
	err := PubKey(in, &out)
	if err != nil {
		t.Errorf("Failed to PubKey %s", err)
	}

	if examplePublicKey+"\n" != out.String() {
		t.Errorf("Expected to be equal\n  %s\n  %s", examplePublicKey, out.String())
	}
}

func TestEncryptMissingPrivateKey(t *testing.T) {
	t.Parallel()

	in := bytes.NewBufferString(exampleMsg)
	var out bytes.Buffer
	err := Encrypt(in, &out)
	if ErrMissingPrivateKey != err {
		t.Errorf("Expected %s but got %s", ErrMissingPrivateKey, err)
	}
}

func TestEncryptMessage(t *testing.T) {
	in := bytes.NewBufferString(exampleMsg)
	var out bytes.Buffer
	privateKey = examplePrivateKey
	peerKeys = []string{examplePublicKey}
	defer resetKeys()

	err := Encrypt(in, &out)
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}
	t.Logf("Message: %s", base64.RawStdEncoding.EncodeToString(out.Bytes()))
}

func TestDecryptMessage(t *testing.T) {
	rawMsg, _ := base64.RawStdEncoding.DecodeString("AW3N+2Gy/TI0d27+1p9ZxI9psgi6kQBK24Lb7DMI9SgCMSoWLIiX46P4wNmeSB5wAdYrkb9Yn4T0UTrDpCZnm7ZXouCxmnL5Dt2XpDDW6MBUCg/up1JfxqASqFaH3DyM52aHlty+4HWfEy0R")

	in := bytes.NewBuffer(rawMsg)
	var out bytes.Buffer
	privateKey = examplePrivateKey
	defer resetKeys()

	err := Decrypt(in, &out)
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}
	if out.String() != exampleMsg {
		t.Errorf("Expected to be equal\n'%s'\n'%s'", out.String(), exampleMsg)
	}
}

func TestEncryptAndDecryptMultipeRecipients(t *testing.T) {
	in := bytes.NewBufferString(exampleMsg)
	var enc bytes.Buffer
	var dec bytes.Buffer

	defer resetKeys()

	privateKey1, _ := alex.GeneratePrivateKey(rand.Reader)
	publicKey1 := privateKey1.PublicKey()
	privateKey2, _ := alex.GeneratePrivateKey(rand.Reader)
	publicKey2 := privateKey2.PublicKey()

	peerKeys = []string{
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		publicKey1.String(),
		publicKey2.String(),
		examplePublicKey,
	}

	privateKey = examplePrivateKey
	if err := Encrypt(in, &enc); err != nil {
		t.Fatalf("Unexpected encrypt error: %s", err)
	}

	fmt.Println("Message:", base64.RawStdEncoding.EncodeToString(enc.Bytes()), "\n")

	privateKey = privateKey1.String()
	tmpEncode := bytes.NewBuffer(enc.Bytes())
	if err := Decrypt(tmpEncode, &dec); err != nil {
		t.Fatalf("Unexpected decrypt error: %s", err)
	}

	if dec.String() != exampleMsg {
		t.Fatalf("Message not equal\n`%s`\n`%s`", dec.String(), exampleMsg)
	}

	dec.Reset()
	privateKey = privateKey2.String()
	tmpEncode = bytes.NewBuffer(enc.Bytes())
	if err := Decrypt(tmpEncode, &dec); err != nil {
		t.Fatalf("Unexpected decrypt error: %s", err)
	}

	if dec.String() != exampleMsg {
		t.Fatalf("Message not equal\n`%s`\n`%s`", dec.String(), exampleMsg)
	}

	dec.Reset()
	privateKey = examplePrivateKey
	tmpEncode = bytes.NewBuffer(enc.Bytes())
	if err := Decrypt(tmpEncode, &dec); err != nil {
		t.Fatalf("Unexpected decrypt error: %s", err)
	}

	if dec.String() != exampleMsg {
		t.Fatalf("Message not equal\n`%s`\n`%s`", dec.String(), exampleMsg)
	}
}

func resetKeys() {
	privateKey = ""
	peerKeys = []string{}
}
