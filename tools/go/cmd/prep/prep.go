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
	fmt.Fprintf(os.Stderr, "usage: prep lfile kfile1 (-p | kfile2) kfile_size\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("SealFs: ")
	ispass := false
	var args []string
	for _, a := range os.Args {
		if a == "-p" {
			ispass = true
			continue
		}
		args = append(args, a)
	}
	la := len(args)
	if (!ispass && la != 5) || (ispass && la != 4) {
		usage()
	}
	keysize, err := strconv.Atoi(args[len(args)-1])
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
	if !ispass {
		err = prepfiles.PrepKeyFiles(args[2], args[3], int64(keysize), magic)
		if err != nil {
			log.Fatalf("cannot create %s or %s: %s\n", args[2], args[3], err)
		}
	} else {
		err = prepfiles.PassPrepKeyFile(args[2], int64(keysize), magic)
		if err != nil {
			log.Fatalf("cannot create %s: %s\n", args[2], err)
		}
	}
}
