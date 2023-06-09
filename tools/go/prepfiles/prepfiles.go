package prepfiles

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/headers"
	"syscall"
)

func Inode(fname string) (inode uint64, err error) {
	file, err := os.Open(fname)
	if err != nil {
		return 0, fmt.Errorf("can't open %s", fname)
	}
	fi, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("can't stat %s", fname)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("Not a syscall.Stat_t zzz")
	}
	return stat.Ino, nil
}

func CreateLogFile(name string, magic uint64) error {
	lf, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %s", name, err)
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
	kh := &headers.KeyFileHeader{Magic: magic, Burnt: headers.SizeofKeyfileHeader}
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
		return fmt.Errorf("size too small for keystream %d", size)
	}
	w := io.MultiWriter(k1, k2)
	_, err = io.CopyN(w, rand.Reader, size)
	return err
}
