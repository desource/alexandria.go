package alex

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt(data []byte, privateKey *PrivateKey) (out []byte, err error) {
	var nonce [aes.BlockSize]byte
	copy(nonce[:], data[:aes.BlockSize])

	var peerPublicKey PublicKey
	copy(peerPublicKey[:], data[aes.BlockSize:])

	offset := aes.BlockSize + len(peerPublicKey)
	recipients, i := readRecipientCount(data[offset:]) // TODO check for overflow
	offset += i + 1

	message := data[(offset + (int(recipients) * sessionKeyLen)):]

	// for each recipient
	for r := 0; r < int(recipients); r++ {
		shared := privateKey.sharedKey(&peerPublicKey)

		sharedAes, err := aes.NewCipher(shared[:])
		if err != nil {
			return nil, err
		}
		var sessionKey sessionKey
		iv := make([]byte, aes.BlockSize)
		copy(iv, nonce[:])
		// xor with a counter for each recipient
		iv[0] = nonce[0] ^ byte(r)
		iv[1] = nonce[1] ^ byte(r>>1)
		iv[2] = nonce[2] ^ byte(r>>2)
		iv[3] = nonce[3] ^ byte(r>>3)
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
