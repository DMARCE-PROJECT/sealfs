package prepfiles

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/headers"
)

func CreateLogFile(name string, magic uint64) error {
	lf, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %s\n", name, err)
	}
	defer lf.Close()
	lh := &headers.LogFileHeader{Magic: magic}
	return lh.WriteHeader(lf)
}

func CreateKeyFile(name string, magic uint64) (kf *os.File, err error) {
	kf, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", name, err)
	}
	kh := &headers.KeyFileHeader{Magic: magic, Burnt: 0}
	if err = kh.WriteHeader(kf); err != nil {
		return nil, err
	}
	return kf, err
}

func PrepKeyFiles(name string, name2 string, size int64, magic uint64) (err error) {
	var (
		k1 *os.File
		k2 *os.File
	)
	if k1, err = CreateKeyFile(name, magic); err != nil {
		return err
	}
	defer k1.Close()
	if k2, err = CreateKeyFile(name2, magic); err != nil {
		return err
	}
	defer k2.Close()
	if size == 0 {
		log.Printf("warning, 0 size keystream %s\n", name)
	}
	if size < 0 {
		return fmt.Errorf("size too small for keystream %d\n", size)
	}
	w := io.MultiWriter(k1, k2)
	_, err = io.CopyN(w, rand.Reader, size)
	return err
}
