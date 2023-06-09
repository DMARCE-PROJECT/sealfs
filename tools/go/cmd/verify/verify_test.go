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

const EXDIR = "../../files"

func exampleDesc(dir string, kalpha string, kbeta string) (sf *sealdesc.SealFsDesc, nRatchet uint64, err error) {
	lname := sealdesc.DefaultLogfileName
	typelog := entries.LogSilent
	lpath := fmt.Sprintf("%s/%s", dir, lname)

	desc, err := sealdesc.OpenDesc(kbeta, lpath, dir, typelog)
	if err != nil {
		return nil, 0, err
	}
	_, nRatchet, err = desc.CheckKeystream(kalpha)
	if err != nil {
		return nil, 0, err
	}
	return desc, nRatchet, nil
}

// can probably factor out main an this example
// lots of repeated code
func TestExample(t *testing.T) {
	var err error
	region := sealdesc.Region{}

	dir := EXDIR + "/example"

	zzzinode, err := prepfiles.Inode(EXDIR + "/example/zzz")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}

	zzz2inode, err := prepfiles.Inode(EXDIR + "/example/zzz.1")
	if err != nil {
		t.Errorf("cannot find inode: %s", err)
	}
	renames := sealdesc.Renames{
		zzzinode:  {Inode: zzzinode, NewInode: 5243063},
		zzz2inode: {Inode: zzz2inode, NewInode: 5243058},
	}

	desc, nRatchet, err := exampleDesc(dir, EXDIR+"/k1example", EXDIR+"/k2example")
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
		region := sealdesc.Region{}

		dir := EXDIR + "/example"
		zzzinode, err := prepfiles.Inode(EXDIR + "/example/zzz")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}

		zzz2inode, err := prepfiles.Inode(EXDIR + "/example/zzz.1")
		if err != nil {
			t.Errorf("cannot find inode: %s", err)
		}
		renames := sealdesc.Renames{
			zzzinode:  {Inode: zzzinode, NewInode: 5243063},
			zzz2inode: {Inode: zzz2inode, NewInode: 5243058},
		}

		desc, nRatchet, err := exampleDesc(dir, EXDIR+"/k1example", EXDIR+"/k2example")
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
