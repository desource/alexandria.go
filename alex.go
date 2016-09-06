package alex

import "errors"

var (
	ErrEmptyKey            = errors.New("Empty key")
	ErrInsufficientEntropy = errors.New("Insufficient random entropy")
	ErrFailedToDecrypt     = errors.New("failed to decrypt")
)

type sessionKey [32]byte

const maxRecipientCountLen16 = 3
