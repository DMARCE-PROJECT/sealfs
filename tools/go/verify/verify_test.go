package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/headers"
	"sealfs/sealfs/verifdesc"
	"syscall"
	"testing"
)

func inode(fname string) (inode uint64, err error) {
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

func example_Desc(dir string, kalpha string, kbeta string) (sf *verifdesc.SealFsDesc, err error) {
	lname := verifdesc.DefaultLogfileName
	typeLog := entries.LogSilent
	lpath := fmt.Sprintf("%s/%s", dir, lname)
	alphaf, err := os.Open(kalpha)
	if err != nil {
		return nil, fmt.Errorf("can't open %s\n", kalpha)
	}
	defer alphaf.Close()
	betaf, err := os.Open(kbeta)
	if err != nil {
		return nil, fmt.Errorf("can't open %s", kbeta)
	}
	lf, err := os.Open(lpath)
	if err != nil {
		return nil, fmt.Errorf("can't open %s", lpath)
	}

	kalphaHeader := &headers.KeyFileHeader{}
	err = kalphaHeader.FillHeader(alphaf)
	if err != nil {
		return nil, fmt.Errorf("can't read kalphahdr")
	}
	kbetaHeader := &headers.KeyFileHeader{}
	err = kbetaHeader.FillHeader(betaf)
	if err != nil {
		return nil, fmt.Errorf("can't read kbetahdr")
	}
	logHeader := &headers.LogFileHeader{}
	err = logHeader.FillHeader(lf)
	if err != nil {
		return nil, fmt.Errorf("can't read lheader")
	}
	if logHeader.Magic != kalphaHeader.Magic || logHeader.Magic != kbetaHeader.Magic {
		return nil, fmt.Errorf("magic numbers don't match")
	}
	err = verifdesc.CheckKeyStreams(alphaf, betaf, kalphaHeader.Burnt)
	if err != nil {
		return nil, fmt.Errorf("checkkeystreams: %s", err)
	}
	desc := verifdesc.NewSealFsDesc(betaf, lf, dir, typeLog)
	return desc, nil
}

// can probably factor out main an this example
// lots of repeated code
func TestExample(t *testing.T) {
	var err error
	nRatchet := NRatchetDefault
	region := verifdesc.Region{}

	dir := "../files/example"

	zzzinode, err := inode("../files/example/zzz")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}

	zzz2inode, err := inode("../files/example/zzz.1")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}
	renames := verifdesc.Renames{
		zzzinode:  {zzzinode, 5243063},
		zzz2inode: {zzz2inode, 5243058},
	}

	desc, err := example_Desc(dir, "../files/k1example", "../files/k2example")
	if err != nil {
		t.Errorf("cannot make example desc: %s", err)
	}
	defer desc.Close()

	err = desc.Verify(region, renames, nRatchet)
	if err != nil {
		t.Error(err)
	}
}

type FuzzyReader struct {
	b byte
	r io.ReadCloser
}

func (fr *FuzzyReader) Read(p []byte) (n int, err error) {
	n, err = fr.r.Read(p)
	if err != nil {
		return n, err
	}
	off := int(fr.b) % len(p)
	b := p[off]
	p[off] ^= fr.b
	if b == p[off] {
		return 0, io.EOF
	}
	return n, err
}
func (fr *FuzzyReader) Close() error {
	return fr.r.Close()
}

func FuzzExampleLog(f *testing.F) {
	for _, seed := range []byte{3, 4, 5, 0xff, 0xaa, 0xb, 0x10} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in byte) {
		var err error
		nRatchet := NRatchetDefault
		region := verifdesc.Region{}

		dir := "../files/example"
		zzzinode, err := inode("../files/example/zzz")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}

		zzz2inode, err := inode("../files/example/zzz.1")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}
		renames := verifdesc.Renames{
			zzzinode:  {zzzinode, 5243063},
			zzz2inode: {zzz2inode, 5243058},
		}

		desc, err := example_Desc(dir, "../files/k1example", "../files/k2example")
		if err != nil {
			t.Errorf("cannot make example desc: %s", err)
		}
		desc.SetLogFile(&FuzzyReader{in, desc.LogFile()})
		defer desc.Close()
		err = desc.Verify(region, renames, nRatchet)
		if err == nil {
			t.Error(errors.New("verify should fail"))
		}
	})
}
