package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sealfs/sealfs/prepfiles"
	"strconv"
)

var DebugPrep = false

func usage() {
	fmt.Fprintf(os.Stderr, "usage: prep lfile kfile1 kfile2 kfile_size\n")
	os.Exit(2)
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

	err = prepfiles.CreateLogFile(args[1], magic)
	if err != nil {
		log.Fatalf("cannot create %s: %s\n", args[1], err)
	}
	err = prepfiles.PrepKeyFiles(args[2], args[3], int64(keysize), magic)
	if err != nil {
		log.Fatalf("cannot create %s or %s: %s\n", args[2], args[3], err)
	}
}
