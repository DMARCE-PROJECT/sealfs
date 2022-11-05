package main

import (
	"testing"
	"os"
	"fmt"
	"sealfs/sealfs/entries"
	"syscall"
)

func inode(fname string) (inode uint64, err error){
	file, err := os.Open(fname)
	if err != nil {
		return 0, fmt.Errorf("can't open %s\n", fname)
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

func Test_Example(t *testing.T) {
	var err error
	nRatchet := NRatchetDefault
	region := Region{uint64(0), uint64(0), uint64(0)}
	lname := DefaultLogfileName
	typeLog := entries.LogNone
	dir := "../files/example"
	kalpha := "../files/k1example"
	kbeta := "../files/k2example"
	zzzinode, err := inode("../files/example/zzz")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}

	zzz2inode, err := inode("../files/example/zzz.1")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}
	renames := Renames{
		zzz2inode: {zzz2inode, 5243058},
		zzzinode: {zzzinode, 5243063},
	}

	lpath := fmt.Sprintf("%s/%s", dir, lname)
	alphaf, err := os.Open(kalpha)
	if err != nil {
		t.Errorf("can't open %s\n", kalpha)
	}
	defer alphaf.Close()
	betaf, err := os.Open(kbeta)
	if err != nil {
		t.Errorf("can't open %s", kbeta)
	}
	defer betaf.Close()
	lf, err := os.Open(lpath)
	if err != nil {
		t.Errorf("can't open %s", lpath)
	}
	fmt.Fprintf(os.Stderr, "lf %s\n", lpath)
	defer lf.Close()

	kalphaHeader := &KeyFileHeader{}
	err = kalphaHeader.FillHeader(alphaf)
	if err != nil {
		t.Error("can't read kalphahdr")
	}
	kbetaHeader := &KeyFileHeader{}
	err = kbetaHeader.FillHeader(betaf)
	if err != nil {
		t.Error("can't read kbetahdr")
	}
	logHeader := &LogFileHeader{}
	err = logHeader.FillHeader(lf)
	if err != nil {
		t.Error("can't read lheader")
	}
	if logHeader.magic != kalphaHeader.magic || logHeader.magic != kbetaHeader.magic {
		t.Error("magic numbers don't match")
	}
	fmt.Printf("k1 burnt: %d\n", kalphaHeader.burnt)
	err = checkKeyStreams(alphaf, betaf, kalphaHeader.burnt)
	if err != nil {
		t.Errorf("checkkeystreams: %s", err)
	}
	for _, r := range renames {
		fmt.Fprintf(os.Stderr, "rename inode %s\n", r)
	}
	desc := &SealFsDesc{kf: betaf, lf: lf, dirPath: dir, typeLog: typeLog}

	err = verify(desc, region, renames, nRatchet)
	if err != nil {
		t.Error(err)
	}

}