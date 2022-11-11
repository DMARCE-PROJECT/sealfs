package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/headers"
	"strconv"
)

var DebugPrep = false

func usage() {
	fmt.Fprintf(os.Stderr, "usage: prep lfile kfile1 kfile2 kfile_size")
	os.Exit(2)
}

func createKeyFile(name string, magic uint64) (kf *os.File, err error) {
	kf, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", name, err)
	}
	kh := &headers.LogFileHeader{Magic: magic}
	if err = kh.WriteHeader(kf); err != nil {
		return nil, err
	}
	return kf, err
}

func prepKeyFiles(name string, name2 string, size int64, magic uint64) (err error) {
	var (
		k1 *os.File
		k2 *os.File
	)
	if k1, err = createKeyFile(name, magic); err != nil {
		return err
	}
	defer k1.Close()
	if k2, err = createKeyFile(name2, magic); err != nil {
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

func createLogFile(name string, magic uint64) error {
	lf, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %s\n", name, err)
	}
	defer lf.Close()
	lh := &headers.LogFileHeader{Magic: magic}
	return lh.WriteHeader(lf)
}

func main() {
	log.SetPrefix("SealFs: ")
	args := os.Args
	if len(args) != 5 {
		usage()
	}
	keysize, err := strconv.Atoi(args[4])
	if err != nil {
		usage()
	}
	b := make([]byte, 8)
	n, err := rand.Read(b)
	if err != nil || n != len(b) {
		log.Fatalf("error creating magic %s", err)
	}
	magic := binary.LittleEndian.Uint64(b)
	if DebugPrep {
		fmt.Fprintf(os.Stderr, "magic: %x\n", magic)
	}

	err = createLogFile(args[1], magic)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", args[2], err)
	}
	err = prepKeyFiles(args[2], args[3], int64(keysize), magic)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", args[2], err)
	}
}
