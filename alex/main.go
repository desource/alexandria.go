package main // import "desource.net/alex/alex"

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"desource.net/alex"
)

// TODO set build time
const VERSION = "DEV"

var (
	ErrMissingPrivateKey = errors.New("missing --private-key")
)

var (
	privateKey string
	peerKeys   recipientKeys

	debugMode bool
)

func main() {
	proc := filepath.Base(os.Args[0])
	var err error
	var args []string

	var cmd string
	if len(os.Args) > 1 {
		cmd = os.Args[1]
		args = os.Args[2:]
	}

	// check for debug mode
	switch cmd {
	case "-d", "-debug", "--debug":
		debugMode = true
		if len(os.Args) > 2 {
			cmd = os.Args[2]
			args = os.Args[3:]
		} else {
			cmd = ""
			args = []string{}
		}
	}

	switch cmd {
	case "genkey":
		err = GenKey(os.Stdout)

	case "pubkey":
		err = PubKey(os.Stdin, os.Stdout)

	case "enc", "encrypt":
		flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
		flags.Usage = func() {}

		flags.StringVar(&privateKey, "key", "", "")
		flags.StringVar(&privateKey, "private-key", "", "")
		flags.Var(&peerKeys, "r", "")
		flags.Var(&peerKeys, "recipient", "")
		// flags.BoolVar(&ammor, "a", false, "")
		// flags.BoolVar(&ammor, "ammor", false, "")

		if err := flags.Parse(args); err != nil {
			fmt.Fprintf(os.Stderr, "%s %s: %s\n", proc, cmd, err)
			os.Exit(2)
		}
		err = Encrypt(os.Stdin, os.Stdout)

		// TODO specific help

	case "dec", "decrypt":
		flags := flag.NewFlagSet("decrypt", flag.ContinueOnError)
		flags.Usage = func() {}

		flags.StringVar(&privateKey, "k", "", "")
		flags.StringVar(&privateKey, "key", "", "")

		if err := flags.Parse(args); err != nil {
			fmt.Fprintf(os.Stderr, "%s %s: %s\n", proc, cmd, err)
			os.Exit(2)
		}
		err = Decrypt(os.Stdin, os.Stdout)

	case "v", "version", "-v", "--version":
		Version(os.Stdout)

	case "", "h", "help", "-h", "--help":
		DefaultHelp(os.Stdout)

	default:
		err = fmt.Errorf("unexpected command '%s'", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", proc, err)
		os.Exit(1)
	}
}

func GenKey(out io.Writer) error {
	key, err := alex.GeneratePrivateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, key.String())
	return nil
}

func PubKey(in io.Reader, out io.Writer) error {
	var key string
	_, err := fmt.Fscanln(in, &key)
	if err != nil {
		// TODO improve errors?
		return err
	}

	priv, err := alex.DecodePrivateKey(key)
	if err != nil {
		return err
	}

	pub := priv.PublicKey()
	fmt.Fprintln(out, pub.String())
	return nil
}

type recipientKeys []string

func (keys *recipientKeys) String() string {
	return ""
}

func (keys *recipientKeys) Set(v string) error {
	*keys = append(*keys, v)
	return nil
}

func (keys *recipientKeys) DecodeKeys() (publicKeys []*alex.PublicKey, err error) {
	var publicKey alex.PublicKey
	for _, key := range *keys {
		publicKey, err = alex.DecodePublicKey(key)
		if err != nil {
			return
		}
		publicKeys = append(publicKeys, &publicKey)
	}
	return
}

func Encrypt(in io.Reader, out io.Writer) error {
	if privateKey == "" {
		return ErrMissingPrivateKey
	}
	key, err := alex.DecodePrivateKey(privateKey)
	if err != nil {
		return err
	}
	peers, err := peerKeys.DecodeKeys()
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		warn("no recpient specified, defaulting to private key")
		pubKey := key.PublicKey()
		peers = append(peers, &pubKey)
	}

	if debugMode {
		debug("Private key %s", key)
		debug("Public keys")
		for i, p := range peers {
			debug("%3d] %s", i+1, p)
		}
	}

	message, err := ioutil.ReadAll(in)
	if err != nil {
		// TODO improve error
		return err
	}

	enc, err := alex.Encrypt(message, &key, peers...)
	if err != nil {
		// TODO: improve error
		return err
	}
	_, err = out.Write(enc)
	if err != nil {
		// TODO: improve error
		return err
	}

	return nil
}

func Decrypt(in io.Reader, out io.Writer) error {
	if privateKey == "" {
		return ErrMissingPrivateKey
	}
	key, err := alex.DecodePrivateKey(privateKey)
	if err != nil {
		return err
	}
	debug("Private key: %s", key)

	message, err := ioutil.ReadAll(in)
	if err != nil {
		// TODO improve error
		return err
	}

	dec, err := alex.Decrypt(message, &key)
	if err != nil {
		// TODO: improve error
		return err
	}
	_, err = out.Write(dec)
	if err != nil {
		// TODO: improve error
		return err
	}

	return nil
}

func Version(out io.Writer) {
	fmt.Fprintln(out, `alex version:`, VERSION)
}

func DefaultHelp(out io.Writer) {
	fmt.Fprint(out, `NAME:
  alex(andria) - A command line tool to encrypt and decrypt messages

USAGE:
  alex [global options] command [command options]

COMMANDS:
  genkey            generate a new private key
  pubkey            generate public key from private key
  encrypt, enc      encrypt a message
  decrypt, dec      decrypt a message
  version           show version info
  help              show help for a command

GLOBAL OPTIONS:
  -d, --debug       output debug info to stderr
`)
}

func warn(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARN: "+msg+"\n", args...)
}

func debug(msg string, args ...interface{}) {
	if debugMode {
		fmt.Fprintf(os.Stderr, "DEBUG: "+msg+"\n", args...)
	}
}
