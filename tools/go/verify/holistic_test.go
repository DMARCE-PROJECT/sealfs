package main_test

import (
	"fmt"
	"io"
	"os"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/headers"
	"sealfs/sealfs/prepfiles"
	"sealfs/sealfs/sealdesc"
	"testing"
)

const (
	MagicTest    = 0xbabe6666babe6666
	KeySizeTest  = 16 * 1024 * 1024
	NRatchetTest = uint64(17)
)

func testlog(t *testing.T, filllog func(lfname string, sdir string, k1 string) error) {
	rootdir, err := os.MkdirTemp("", "sealfstest")
	if err != nil {
		t.Errorf("creating temporary directory: %s", err)
		return
	}
	defer os.RemoveAll(rootdir)
	sealdir := fmt.Sprintf("%s/sealdir", rootdir)
	err = os.Mkdir(sealdir, 0700)
	if err != nil {
		t.Errorf("creating sealfs dir: %s", err)
		return
	}
	logfile := fmt.Sprintf("%s/%s", sealdir, sealdesc.DefaultLogfileName)
	k1file := fmt.Sprintf("%s/k1", rootdir)
	k2file := fmt.Sprintf("%s/k2", rootdir)

	err = prepfiles.CreateLogFile(logfile, MagicTest)
	if err != nil {
		t.Errorf("cannot create %s: %s\n", logfile, err)
		return
	}
	err = prepfiles.PrepKeyFiles(k1file, k2file, KeySizeTest, MagicTest)
	if err != nil {
		t.Errorf("cannot create %s or %s: %s\n", k1file, k2file, err)
		return
	}
	if filllog != nil {
		err = filllog(logfile, sealdir, k1file)
		if err != nil {
			t.Errorf("filling log %s in %s: %s", logfile, sealdir, err)
			return
		}
	}

	nRatchet := NRatchetTest
	region := sealdesc.Region{}
	renames := sealdesc.Renames{}
	typeLog := entries.LogSilent
	desc, err := sealdesc.OpenDesc(k2file, logfile, sealdir, typeLog)
	if err != nil {
		t.Errorf("cannot open example desc: %s", err)
		return
	}
	defer desc.Close()
	_, err = desc.CheckKeystream(k1file)
	if err != nil {
		t.Errorf("cannot check keystream example desc: %s", err)
		return
	}
	err = desc.Verify(region, renames, nRatchet)
	if err == nil && filllog == nil {
		t.Error("there are no entries in log, should be an error")
		return
	}
	if err != nil && filllog != nil {
		t.Errorf("error verifying: %s", err)
		return
	}
	if err != nil && filllog == nil {
		return //ok, error because it is empty
	}
	if err == nil && filllog != nil {
		return
	}
	t.Errorf("should not happen: %s", err)
}

func TestEmpty(t *testing.T) {
	testlog(t, nil)
}

const NRounds = 10

func TestSome(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) error {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err)
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err)
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err)
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err)
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err)
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err)
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err)
			}
			entry := &entries.LogfileEntry{
				RatchetOffset: roff % nRatchet,
				Inode:         inode,
				FileOffset:    uint64(len(b)) * i,
				WriteCount:    uint64(len(b)),
				KeyFileOffset: headers.SizeofKeyfileHeader + (roff/nRatchet)*entries.FprSize,
			}
			err = entry.ReMac(ul, k1f, &keyC, nRatchet)
			if err != nil {
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err)
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err)
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err)
			}
			roff++
		}
		return nil
	}
	testlog(t, filllog)
}
func TestInv(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) error {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err)
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err)
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err)
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err)
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err)
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err)
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err)
			}
		}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			entry := &entries.LogfileEntry{
				RatchetOffset: roff % nRatchet,
				Inode:         inode,
				FileOffset:    uint64(len(b)) * (NRounds*nRatchet - i - 1),
				WriteCount:    uint64(len(b)),
				KeyFileOffset: headers.SizeofKeyfileHeader + (roff/nRatchet)*entries.FprSize,
			}
			err = entry.ReMac(ul, k1f, &keyC, nRatchet)
			if err != nil {
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err)
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err)
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err)
			}
			roff++
		}
		return nil
	}
	testlog(t, filllog)
}
