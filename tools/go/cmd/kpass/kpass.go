package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sealfs/sealfs/headers"
	"sealfs/sealfs/prepfiles"
)

var DebugPrep = false

func usage() {
	fmt.Fprintf(os.Stderr, "usage: kpass lfile kfile1 kfile2\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("SealFs: ")
	args := os.Args
	if len(args) != 4 {
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

	alphaf, err := os.Open(args[2])
	if err != nil {
		log.Fatalf("can't open %s\n", args[2])
	}
	defer alphaf.Close()
	kh := &headers.KeyFileHeader{}
	err = kh.FillHeader(alphaf)
	if err != nil {
		log.Fatalf("can't read kalphahdr: %s", err)
	}
	fia, err := alphaf.Stat()
	if err != nil {
		log.Fatalf("can't stat alpha")
	}
	keysize := fia.Size() - headers.SizeofKeyfileHeader
	err = prepfiles.PassPrepKeyFile(args[3], int64(keysize), kh.Magic)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", args[3], err)
	}
}
