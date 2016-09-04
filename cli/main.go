package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/desource/alexandria.go"
)

/*
TODO:
keystore

COMMANDS:
- Generate key
- export/import keys (json)
- encrypt (armour/binary) + filename + recipients
- decyrpt (armour/binary) + filename

ENCRYPTED:
- A13x
- version
- cypher
- recipient count
- encrypted priv key x recipients
- (len + message) encrypted
*/

var message = "Hello world"

func main() {
	privateKey1, err := alexandria.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Private Key: %s\n", privateKey1)

	privateKey2, err := alexandria.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public Key:  %s\n\n", privateKey2.PublicKey())

	out, err := Encrypt(privateKey1, privateKey2.PublicKey(), []byte(message))
	if err != nil {
		panic(err)
	}
	fmt.Println(formatArmored(out))

	v, err := Decrypt(privateKey2, out)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nMessage:\n%s\n", string(v))
}

func Encrypt(privateKey *alexandria.Key, peerPublicKey *alexandria.Key, plaintext []byte) (out []byte, err error) {
	var sessionKey [32]byte
	if err = randNonce(sessionKey[:]); err != nil {
		return nil, err
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
		(1 * len(sessionKey)) +
		aesgcm.Overhead() +
		len(plaintext)

	out = make([]byte, maxLen)

	err = randNonce(out[:nonceLen])
	if err != nil {
		return nil, err
	}
	nonce := out[:nonceLen]
	offset := nonceLen
	copy(out[nonceLen:], publicKey[:])
	offset = offset + len(publicKey)

	l := writeRecipientCount(out[offset:], 1)
	offset = offset + l
	out = out[:maxLen-(maxRecipientCountLen16-l)]

	// For each recpient
	sharedAes, err := aes.NewCipher(privateKey.SharedKey(peerPublicKey)[:])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, []byte(nonce)) // TODO: xor with a counter for each recpient
	stream := cipher.NewCTR(sharedAes, iv)
	stream.XORKeyStream(out[offset:], sessionKey[:])

	// update offset
	offset = offset + (1 * len(sessionKey))

	aesgcm.Seal(out[offset:offset], nonce[:aesgcm.NonceSize()], plaintext, nil)

	return
}

func Decrypt(privateKey *alexandria.Key, data []byte) (out []byte, err error) {
	nonce := data[:aes.BlockSize]

	var peerPublicKey alexandria.Key
	copy(peerPublicKey[:], data[aes.BlockSize:])

	offset := aes.BlockSize + len(peerPublicKey)
	_, i := readRecipientCount(data[offset:]) // TODO check for overflow
	offset += i + 1

	// for each recpient
	var sessionKey alexandria.Key
	sharedAes, err := aes.NewCipher(privateKey.SharedKey(&peerPublicKey)[:])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, []byte(nonce)) // TODO: xor with a counter for each recpient
	stream := cipher.NewCTR(sharedAes, iv)
	stream.XORKeyStream(sessionKey[:], data[offset:offset+len(sessionKey)])

	offset += len(sessionKey)

	sessionAes, err := aes.NewCipher(sessionKey[:])
	if err != nil {
		return nil, err
	}
	aesgcm, _ := cipher.NewGCM(sessionAes)

	message := data[offset:]

	return aesgcm.Open(data[:0], nonce[:aesgcm.NonceSize()], message, nil)
}

const (
	// TODO: should this encode encription type and version?
	prefix     = "-----BEGIN ALEXANDRIA-----\n"
	suffix     = "\n-----END ALEXANDRIA-----"
	lineLength = 64
)

func formatArmored(value []byte) string {
	e := base64.RawStdEncoding
	l := e.EncodedLen(len(value))
	l += (l / lineLength) + 1
	out := make([]byte, len(prefix)+l+len(suffix))

	copy(out, []byte(prefix))
	lb := &lineBreaker{out: out[len(prefix):]}
	enc := base64.NewEncoder(e, lb)

	pos := 0
	for {
		n, _ := enc.Write(value[pos:])
		if n == 0 {
			break
		}
		pos += n
	}
	enc.Close()

	copy(out[len(prefix)+l:], []byte(suffix))

	return string(out)
}

type lineBreaker struct {
	pos int
	out []byte
}

func (l *lineBreaker) Write(b []byte) (n int, err error) {
	start := l.pos
	used := l.pos % (lineLength + 1)
	if used+len(b) < lineLength {
		copy(l.out[l.pos:], b)
		l.pos += len(b)
		return len(b), nil
	}

	n = len(b)
	if n > lineLength-used {
		n = lineLength
	}
	copy(l.out[l.pos:], b[:n])
	l.pos += n
	l.out[l.pos] = '\n'
	l.pos += 1

	for n < len(b) {
		end := len(b) - n
		if end > lineLength {
			end = lineLength
		}

		start := n
		n += end
		copy(l.out[l.pos:], b[start:n])
		if n < len(b) {
			l.pos += end
			l.out[l.pos] = '\n'
			l.pos += 1
		}
	}

	return l.pos - start, nil
}

var (
	ErrInsufficientEntropy = errors.New("Insufficient random entropy")
)

// TODO: change name
func randNonce(nonce []byte) (err error) {
	var n int
	if n, err = rand.Read(nonce); err != nil {
		return
	} else if n != len(nonce) {
		return ErrInsufficientEntropy
	}
	return
}

const maxRecipientCountLen16 = 3

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

func readRecipientCount(buf []byte) (x uint16, i int) {
	var s uint
	for ; ; i++ {
		b := buf[i]
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

/*
func ReadUvarint(r io.ByteReader) (uint64, error) {
   	var x uint64
   	var s uint
   	for i := 0; ; i++ {
   		b, err := r.ReadByte()
   		if err != nil {
   			return x, err
   		}
   		if b < 0x80 {
   			if i > 9 || i == 9 && b > 1 {
   				return x, overflow
   			}
   			return x | uint64(b)<<s, nil
   		}
   		x |= uint64(b&0x7f) << s
   		s += 7
   	}
 }
*/
