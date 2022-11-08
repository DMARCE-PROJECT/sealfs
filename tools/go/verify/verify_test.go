package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sealfs/sealfs/entries"
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

func example_Desc() (sf *SealFsDesc, err error) {
	lname := DefaultLogfileName
	typeLog := entries.LogSilent
	dir := "../files/example"
	kalpha := "../files/k1example"
	kbeta := "../files/k2example"
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

	kalphaHeader := &KeyFileHeader{}
	err = kalphaHeader.FillHeader(alphaf)
	if err != nil {
		return nil, fmt.Errorf("can't read kalphahdr")
	}
	kbetaHeader := &KeyFileHeader{}
	err = kbetaHeader.FillHeader(betaf)
	if err != nil {
		return nil, fmt.Errorf("can't read kbetahdr")
	}
	logHeader := &LogFileHeader{}
	err = logHeader.FillHeader(lf)
	if err != nil {
		return nil, fmt.Errorf("can't read lheader")
	}
	if logHeader.magic != kalphaHeader.magic || logHeader.magic != kbetaHeader.magic {
		return nil, fmt.Errorf("magic numbers don't match")
	}
	err = checkKeyStreams(alphaf, betaf, kalphaHeader.burnt)
	if err != nil {
		return nil, fmt.Errorf("checkkeystreams: %s", err)
	}
	desc := &SealFsDesc{kf: betaf, lf: lf, dirPath: dir, typeLog: typeLog}
	return desc, nil
}

// can probably factor out main an this example
// lots of repeated code
func TestExample(t *testing.T) {
	var err error
	nRatchet := NRatchetDefault
	region := Region{uint64(0), uint64(0), uint64(0)}

	zzzinode, err := inode("../files/example/zzz")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}

	zzz2inode, err := inode("../files/example/zzz.1")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}
	renames := Renames{
		zzzinode:  {zzzinode, 5243063},
		zzz2inode: {zzz2inode, 5243058},
	}

	desc, err := example_Desc()
	if err != nil {
		t.Errorf("cannot make example desc: %s", err)
	}
	defer desc.lf.Close()
	defer desc.kf.Close()

	err = verify(desc, region, renames, nRatchet)
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
		region := Region{uint64(0), uint64(0), uint64(0)}

		zzzinode, err := inode("../files/example/zzz")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}

		zzz2inode, err := inode("../files/example/zzz.1")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}
		renames := Renames{
			zzzinode:  {zzzinode, 5243063},
			zzz2inode: {zzz2inode, 5243058},
		}

		desc, err := example_Desc()
		if err != nil {
			t.Errorf("cannot make example desc: %s", err)
		}
		desc.lf = &FuzzyReader{in, desc.lf}
		defer desc.lf.Close()
		defer desc.kf.Close()
		err = verify(desc, region, renames, nRatchet)
		if err == nil {
			t.Error(errors.New("verify should fail"))
		}
	})
}
