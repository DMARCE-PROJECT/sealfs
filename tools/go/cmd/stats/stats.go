package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/headers"
	"sealfs/sealfs/sealdesc"
)

type Stats struct {
	NWrites   uint64
	AvgCount  float64
	MaxCount  uint64
	FakeCount uint64
}

func (st *Stats) String() string {
	s := fmt.Sprintf("nw: %d, avgc: %f, ", st.NWrites, st.AvgCount)
	s += fmt.Sprintf("maxc: %d, fakec: %d", st.MaxCount, st.FakeCount)
	return s
}

func stats(ef entries.EntryReader) (st *Stats, err error) {
	st = &Stats{}
	for {
		err, entry := ef.ReadEntry()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("can't read from lfile: %s\n", err)
		}
		if entry.Inode == entries.FakeInode {
			st.FakeCount++
			continue
		}
		wc := entry.WriteCount
		if wc > st.MaxCount {
			st.MaxCount = wc
		}
		st.NWrites++
		avgold := st.AvgCount
		st.AvgCount = avgold + (float64(wc)-avgold)/float64(st.NWrites)
	}
	return st, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: stats dir|file\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("SealFs: ")
	if len(os.Args) != 2 {
		usage()
	}
	fname := os.Args[1]
	fi, err := os.Stat(fname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s", fname, err)
		usage()
	}
	if fi.Mode().IsDir() {
		fname = fname + "/" + sealdesc.DefaultLogfileName
	}
	lf, err := os.Open(fname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %s", fname, err)
		usage()
	}
	_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
	if err != nil {
		log.Fatalf("cannot seek %s: %s\n", fname, err)
	}
	ef := entries.NewEntryFile(lf)
	st, err := stats(ef)
	if err != nil {
		log.Fatalf("reading log file %s: %s\n", fname, err)
	}
	fmt.Printf("stats: %s\n", st)

}