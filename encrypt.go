package alex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// TODO move behind interface?
func Encrypt(plaintext []byte, privateKey *PrivateKey, peerPublicKeys ...*PublicKey) (out []byte, err error) {
	// TODO validate peer public keys

	var sessionKey sessionKey
	if n, err := rand.Read(sessionKey[:]); err != nil {
		return nil, err
	} else if err == nil && n != len(sessionKey) {
		return nil, ErrInsufficientEntropy
	}

	sessionAes, err := aes.NewCipher(sessionKey[:])
	if err != nil {
		return nil, err
	}
	aesgcm, _ := cipher.NewGCM(sessionAes)

	publicKey := privateKey.PublicKey()

	nonceLen := aes.BlockSize //aesgcm.NonceSize()

	maxLen := nonceLen +
		len(publicKey) +
		maxRecipientCountLen16 +
		(len(peerPublicKeys) * len(sessionKey)) +
		aesgcm.Overhead() +
		len(plaintext)

	out = make([]byte, maxLen)

	if n, err := rand.Read(out[:nonceLen]); err != nil {
		return nil, err
	} else if n != nonceLen {
		return nil, ErrInsufficientEntropy
	}
	nonce := out[:nonceLen]
	offset := nonceLen
	copy(out[nonceLen:], publicKey[:])
	offset = offset + len(publicKey)

	l := writeRecipientCount(out[offset:], uint16(len(peerPublicKeys)))
	offset = offset + l
	out = out[:maxLen-(maxRecipientCountLen16-l)]

	iv := make([]byte, aes.BlockSize)

	// For each recipient
	for r, peerPublicKey := range peerPublicKeys {
		shared := privateKey.sharedKey(peerPublicKey)

		sharedAes, err := aes.NewCipher(shared[:])
		if err != nil {
			return nil, err
		}
		copy(iv, []byte(nonce))
		// xor with a counter for each recipient
		iv[0] = nonce[0] ^ byte(r)
		iv[1] = nonce[1] ^ byte(r>>1)
		iv[2] = nonce[2] ^ byte(r>>2)
		iv[3] = nonce[3] ^ byte(r>>3)
		stream := cipher.NewCTR(sharedAes, iv)
		stream.XORKeyStream(out[offset:], sessionKey[:])

		// update offset
		offset = offset + len(sessionKey)
	}

	aesgcm.Seal(out[offset:offset], nonce[:aesgcm.NonceSize()], plaintext, nil)

	return
}

func writeRecipientCount(out []byte, x uint16) int {
	i := 0
	for x >= 0x80 {
		out[i] = byte(x) | 0x80
		x >>= 7
		i++
	}
	out[i] = byte(x)
	return i + 1
}
