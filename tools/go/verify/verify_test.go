package main

import (
	"errors"
	"fmt"
	"io"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/prepfiles"
	"sealfs/sealfs/sealdesc"
	"testing"
)

func example_Desc(dir string, kalpha string, kbeta string) (sf *sealdesc.SealFsDesc, err error) {
	lname := sealdesc.DefaultLogfileName
	typeLog := entries.LogSilent
	lpath := fmt.Sprintf("%s/%s", dir, lname)

	desc, err := sealdesc.OpenDesc(kbeta, lpath, dir, typeLog)
	if err != nil {
		return nil, err
	}
	_, err = desc.CheckKeystream(kalpha)
	if err != nil {
		return nil, err
	}
	return desc, nil
}

// can probably factor out main an this example
// lots of repeated code
func TestExample(t *testing.T) {
	var err error
	nRatchet := NRatchetDefault
	region := sealdesc.Region{}

	dir := "../files/example"

	zzzinode, err := prepfiles.Inode("../files/example/zzz")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}

	zzz2inode, err := prepfiles.Inode("../files/example/zzz.1")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}
	renames := sealdesc.Renames{
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
		region := sealdesc.Region{}

		dir := "../files/example"
		zzzinode, err := prepfiles.Inode("../files/example/zzz")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}

		zzz2inode, err := prepfiles.Inode("../files/example/zzz.1")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}
		renames := sealdesc.Renames{
			zzzinode:  {zzzinode, 5243063},
			zzz2inode: {zzz2inode, 5243058},
		}

		desc, err := example_Desc(dir, "../files/k1example", "../files/k2example")
		if err != nil {
			t.Errorf("cannot make example desc: %s", err)
		}
		defer desc.Close()
		desc.SetLogFile(&FuzzyReader{in, desc.LogFile()})
		err = desc.Verify(region, renames, nRatchet)
		if err == nil {
			t.Error(errors.New("verify should fail"))
		}
	})
}
