package prepfiles

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"io"
	"log"
	"os"
	"sealfs/sealfs/entries"
	"syscall"
)

type keyReader struct {
	offset uint64
	state  [entries.FprSize]byte
	nLeft  int
	key    [entries.FprSize]byte
}

const nIterKeyDeriv = 32768 * 4

func NewKeyReader(pass []byte, magic uint64) (keyr *keyReader, err error) {
	//magic is the salt
	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, magic)
	dk, err := scrypt.Key(pass, salt, nIterKeyDeriv, 8, 1, len(keyr.state))
	if err != nil {
		return nil, err
	}
	keyr = &keyReader{}
	copy(keyr.state[:], dk)

	//delete the password and temporary key
	_, err = io.ReadFull(rand.Reader, pass)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(rand.Reader, dk)
	if err != nil {
		return nil, err
	}
	return keyr, nil
}

func (keyr *keyReader) Ratchet() (err error) {
	//derive state
	mac := hmac.New(sha256.New, keyr.state[:])
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, keyr.offset)
	mac.Write(b)
	copy(keyr.state[:], mac.Sum(nil))
	mac.Reset()

	//derive key
	mac = hmac.New(sha256.New, keyr.state[:])
	binary.LittleEndian.PutUint64(b, keyr.offset+1)
	mac.Write(b)
	copy(keyr.key[:], mac.Sum(nil))
	mac.Reset()
	keyr.offset += 2
	return nil
}

func (keyr *keyReader) Read(p []byte) (n int, err error) {
	nleft := keyr.nLeft
	off := len(keyr.key) - nleft
	if nleft == 0 {
		keyr.Ratchet()
		off = 0
		nleft = len(keyr.key)
	}
	n = copy(p, keyr.key[off:])
	keyr.nLeft = nleft - n
	return n, nil
}

const MinPassLen = 10

func PassPrepKeyFile(name string, size int64, magic uint64) (err error) {
	var (
		k1 *os.File
	)
	fmt.Fprintf(os.Stderr, "password: ")
	pass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("cannot read password %s", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	//TODO, additional checks?? length??...
	if len(pass) < MinPassLen {
		return fmt.Errorf("password too short: %d bytes", len(pass))
	}

	if k1, err = CreateKeyFile(name, magic); err != nil {
		return err
	}
	defer k1.Close()
	if size == 0 {
		log.Printf("warning, 0 size keystream %s\n", name)
	}
	if size < 0 {
		return fmt.Errorf("size too small for keystream %d", size)
	}
	keyreader, err := NewKeyReader(pass, magic)
	if keyreader == nil {
		return fmt.Errorf("cannot create keyreader: %s", err)
	}
	w := bufio.NewWriter(k1)
	_, err = io.CopyN(w, keyreader, size)
	w.Flush()
	return err
}
