package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/sealdesc"
	"strconv"
	"strings"
)

func setDebugs(d rune) {
	switch d {
	case 'e':
		entries.DebugEntries = true
	case 'k':
		entries.DebugKeyCache = true
	case 'h':
		sealdesc.DebugJQueue = true
	}
}

// not portable, but will still work
// outside of linux nothing is a TTY for now (no colors)
func isatty(file *os.File) bool {
	fd := file.Fd()
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: verify dir kalpha kbeta [-D[e|k]] [-t | -T | -b | -B] [-n lfilename] [-i inode begin end] [-nfs0 nlog0 -nfs1 nlog1...] \n")
	os.Exit(2)
}

func main() {
	var err error
	log.SetPrefix("SealFs: ")
	renames := make(sealdesc.Renames)

	region := sealdesc.Region{}
	lname := sealdesc.DefaultLogfileName
	if len(os.Args) < 3 {
		usage()
	}
	typeLog := entries.LogNone
	dir := os.Args[1]
	kalpha := os.Args[2]
	kbeta := os.Args[3]
	args := os.Args[4:]
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			usage()
		}
		if len(args[i]) < 2 {
			usage()
		}
		switch args[i][1] {
		case 'n':
			if len(args[i:]) < 2 {
				usage()
			}
			lname = args[i+1]
			i += 1
		case 'D':
			if len(args[i]) < 3 {
				usage()
			}
			setDebugs(rune(args[i][2]))
		case 'i':
			r0 := sealdesc.Region{}
			if len(args[i:]) < 3 || region != r0 {
				usage()
			}
			region, err = sealdesc.InodeBegEnd(args[i+1 : i+4])
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot parse inode number %s", err)
				usage()
			}
			i += 3
		case 't':
			typeLog = entries.LogText
			if isatty(os.Stdout) {
				typeLog = entries.LogColText
			}
		case 'T':
			typeLog = entries.LogText
		case 'b':
			typeLog = entries.LogBin
			if isatty(os.Stdout) {
				typeLog = entries.LogColBin
			}
		case 'B':
			typeLog = entries.LogBin
		default:
			if len(args[i]) < 2 || len(args[i:]) < 2 {
				usage()
			}
			oi, err := strconv.Atoi(args[i][1:])
			if err != nil {
				usage()
			}
			ni, err := strconv.Atoi(args[i+1])
			if err != nil {
				usage()
			}
			renames.AddRename(uint64(oi), uint64(ni))
			i++
		}
	}
	lpath := fmt.Sprintf("%s/%s", dir, lname)

	desc, err := sealdesc.OpenDesc(kbeta, lpath, dir, typeLog)
	if err != nil {
		log.Fatal(err)
	}
	defer desc.Close()
	burnt, nRatchet, err := desc.CheckKeystream(kalpha)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("k1 burnt: %d\n", burnt)
	fmt.Fprintf(os.Stderr, "%s", renames)
	err = desc.Verify(region, renames, nRatchet)
	if err != nil {
		log.Fatal(err)
	}
	if region.Inode != 0 {
		log.Printf("WARNING: you SHOULD run a" +
			" complete verification" +
			" to probe that the file has not been truncated\n")
	}
	os.Exit(0)
}
