package alex // import "desource.net/alex"

import "errors"

var (
	ErrEmptyKey            = errors.New("empty key")
	ErrInsufficientEntropy = errors.New("insufficient random entropy")
	ErrFailedToDecrypt     = errors.New("failed to decrypt")
)

const (
	sessionKeyLen          = 32
	maxRecipientCountLen16 = 3
)

type sessionKey [sessionKeyLen]byte
