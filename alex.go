package alex // import "desource.net/alex"

import "errors"

var (
	ErrEmptyKey            = errors.New("empty key")
	ErrInsufficientEntropy = errors.New("insufficient random entropy")
	ErrFailedToDecrypt     = errors.New("failed to decrypt")
)

type sessionKey [32]byte

const maxRecipientCountLen16 = 3
