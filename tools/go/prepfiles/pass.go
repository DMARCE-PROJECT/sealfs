package prepfiles

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
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

const nIterKeyDeriv = 4096

func NewKeyReader(pass []byte, magic uint64) (keyr *keyReader) {
	//magic is the salt
	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, magic)
	dk := pbkdf2.Key(pass, salt, nIterKeyDeriv, len(keyr.state), sha256.New)
	keyr = &keyReader{}
	copy(keyr.state[:], dk)

	//delete the password and temporary key
	_, err := io.ReadFull(rand.Reader, pass)
	if err != nil {
		return nil
	}
	_, err = io.ReadFull(rand.Reader, dk)
	if err != nil {
		return nil
	}
	return keyr
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
	keyr.offset++
	return nil
}

func (keyr *keyReader) Read(p []byte) (n int, err error) {
	if keyr.nLeft != 0 {
		off := len(keyr.key) - keyr.nLeft
		n = copy(p, keyr.key[off:])
		keyr.nLeft -= n
		return n, nil
	}
	keyr.Ratchet()
	n = copy(p, keyr.key[:])
	if n < len(keyr.key) {
		keyr.nLeft = len(keyr.key) - n
	}
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
	keyreader := NewKeyReader(pass, magic)
	if keyreader == nil {
		return fmt.Errorf("cannot create keyreader")
	}
	w := bufio.NewWriter(k1)
	_, err = io.CopyN(w, keyreader, size)
	w.Flush()
	return err
}
