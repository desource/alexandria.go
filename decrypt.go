package alex

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt(data []byte, privateKey *PrivateKey) (out []byte, err error) {
	nonce := data[:aes.BlockSize]

	var peerPublicKey PublicKey
	copy(peerPublicKey[:], data[aes.BlockSize:])

	offset := aes.BlockSize + len(peerPublicKey)
	recipients, i := readRecipientCount(data[offset:]) // TODO check for overflow
	offset += i + 1

	var sessionKey sessionKey
	iv := make([]byte, aes.BlockSize)
	message := data[(offset + (int(recipients) * len(sessionKey))):]

	// for each recpientx
	for r := 0; r < int(recipients); r++ {
		shared := privateKey.sharedKey(&peerPublicKey)
		sharedAes, err := aes.NewCipher(shared[:])
		if err != nil {
			return nil, err
		}
		copy(iv, []byte(nonce)) // TODO: xor with a counter for each recpient
		stream := cipher.NewCTR(sharedAes, iv)
		stream.XORKeyStream(sessionKey[:], data[offset:offset+len(sessionKey)])

		offset += len(sessionKey)

		sessionAes, err := aes.NewCipher(sessionKey[:])
		if err != nil {
			return nil, err
		}
		aesgcm, _ := cipher.NewGCM(sessionAes)

		out, err = aesgcm.Open(data[:0], nonce[:aesgcm.NonceSize()], message, nil)
		if err == nil {
			return out, nil
		}
		// TODO improve error handling?
	}

	return nil, ErrFailedToDecrypt
}

func readRecipientCount(data []byte) (x uint16, i int) {
	var s uint
	for ; ; i++ {
		b := data[i]
		if b < 0x80 {
			if i >= maxRecipientCountLen16 || (i == maxRecipientCountLen16-1) && b > 1 {
				return x, maxRecipientCountLen16 // overflow
			}
			return x | uint16(b)<<s, i
		}
		x |= uint16(b&0x7f) << s
		s += 7
	}
}
