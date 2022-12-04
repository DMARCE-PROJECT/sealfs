package main_test

import (
	"crypto/rand"
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
	KeySizeTest  = 16 * 1024 * 1024 //should be FprSize * (Nrounds/NRatchet)
	NRatchetTest = uint64(17)
)

func UpdateKeyFile(kfname string, magic uint64, burnt uint64) (err error) {
	kf, err := os.OpenFile(kfname, os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %s\n", kfname, err)
	}
	defer kf.Close()
	kh := &headers.KeyFileHeader{Magic: magic, Burnt: burnt}
	if err = kh.WriteHeader(kf); err != nil {
		return err
	}
	_, err = io.CopyN(kf, rand.Reader, int64(burnt-headers.SizeofKeyfileHeader))
	return err
}

func testlog(t *testing.T, filllog func(lfname string, sdir string, k1 string) (error, uint64)) error {
	rootdir, err := os.MkdirTemp("", "sealfstest")
	if err != nil {
		return fmt.Errorf("creating temporary directory: %s", err)
	}
	//fmt.Println(rootdir)
	defer os.RemoveAll(rootdir)
	sealdir := fmt.Sprintf("%s/sealdir", rootdir)
	err = os.Mkdir(sealdir, 0700)
	if err != nil {
		return fmt.Errorf("creating sealfs dir: %s", err)
	}
	logfile := fmt.Sprintf("%s/%s", sealdir, sealdesc.DefaultLogfileName)
	k1file := fmt.Sprintf("%s/k1", rootdir)
	k2file := fmt.Sprintf("%s/k2", rootdir)

	err = prepfiles.CreateLogFile(logfile, MagicTest)
	if err != nil {
		return fmt.Errorf("cannot create %s: %s\n", logfile, err)
	}
	err = prepfiles.PrepKeyFiles(k1file, k2file, KeySizeTest, MagicTest)
	if err != nil {
		return fmt.Errorf("cannot create %s or %s: %s\n", k1file, k2file, err)
	}
	burnt := uint64(0)
	if filllog != nil {
		err, burnt = filllog(logfile, sealdir, k1file)
		if err != nil {
			return fmt.Errorf("filling log %s in %s: %s", logfile, sealdir, err)
		}
		err = UpdateKeyFile(k1file, MagicTest, burnt)
		if err != nil {
			return fmt.Errorf("updating k1 file header: %s", err)
		}
	}

	region := sealdesc.Region{}
	renames := sealdesc.Renames{}
	typeLog := entries.LogSilent
	desc, err := sealdesc.OpenDesc(k2file, logfile, sealdir, typeLog)
	if err != nil {
		return fmt.Errorf("cannot open example desc: %s", err)
	}
	defer desc.Close()
	_, nRatchet, err := desc.CheckKeystream(k1file)
	if err != nil {
		return fmt.Errorf("cannot check keystream example desc [%d]: %s", burnt, err)
	}
	err = desc.Verify(region, renames, nRatchet)
	if err == nil && filllog == nil {
		return fmt.Errorf("there are no entries in log, should be an error")
	}
	if err != nil && filllog != nil {
		return fmt.Errorf("error verifying: %s", err)
	}
	if err != nil && filllog == nil {
		return nil //ok, error because it is empty
	}
	if err == nil && filllog != nil {
		return nil
	}
	return fmt.Errorf("should not happen: %s", err)
}

func TestEmpty(t *testing.T) {
	err := testlog(t, nil)
	if err != nil {
		t.Errorf("%s", err)
	}
}

const NRounds = 10

func TestSome(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) (error, uint64) {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err), 0
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
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err), 0
			}
			roff++
		}
		return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
	}
	err := testlog(t, filllog)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestInv(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) (error, uint64) {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err), 0
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
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err), 0
			}
			roff++
		}
		return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
	}
	err := testlog(t, filllog)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestNotSealed(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) (error, uint64) {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		//not multiple of nRatchet, not sealed
		for i := uint64(0); i < NRounds*nRatchet-3; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err), 0
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
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err), 0
			}
			roff++
		}
		return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
	}
	err := testlog(t, filllog)
	if err == nil {
		t.Errorf("number of entries not a multiple of nratchet, should fail")
	}
}

func TestTamperLog(t *testing.T) {
	filllog := func(lfname string, d string, k1file string) (error, uint64) {
		userlogfile := fmt.Sprintf("%s/xxx", d)
		ul, err := os.Create(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
		}
		defer ul.Close()
		inode, err := prepfiles.Inode(userlogfile)
		if err != nil {
			return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
		}
		lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
		}
		defer lf.Close()
		_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
		}
		k1f, err := os.Open(k1file)
		if err != nil {
			return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
		}
		defer k1f.Close()
		_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
		if err != nil {
			return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
		}
		var keyC entries.KeyCache
		nRatchet := NRatchetTest
		roff := uint64(0)
		keyC.Drop()
		b := []byte{'a', 'b', 'c', 'd', 'e'}
		for i := uint64(0); i < NRounds*nRatchet; i++ {
			_, err := ul.Write(b)
			if err != nil {
				return fmt.Errorf("writing to user file: %s", err), 0
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
				return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
			}
			if i == NRounds*nRatchet/2 {
				entry.WriteCount = ^entry.WriteCount
			}
			be, err := entry.MarshalBinary()
			if err != nil {
				return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
			}
			_, err = lf.Write(be)
			if err != nil {
				return fmt.Errorf("writing to sealfs log: %s", err), 0
			}
			roff++
		}
		return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
	}
	err := testlog(t, filllog)
	if err == nil {
		t.Errorf("should not have verified, tampered write count")
	}
}

func FuzzTamperEntry(f *testing.F) {
	for _, seed := range []byte{3, 4, 5, 0xff, 0xaa, 0xb, 0x10} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in byte) {
		istamper := false
		filllog := func(lfname string, d string, k1file string) (error, uint64) {
			userlogfile := fmt.Sprintf("%s/xxx", d)
			ul, err := os.Create(userlogfile)
			if err != nil {
				return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
			}
			defer ul.Close()
			inode, err := prepfiles.Inode(userlogfile)
			if err != nil {
				return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
			}
			lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
			}
			defer lf.Close()
			_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
			if err != nil {
				return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
			}
			k1f, err := os.Open(k1file)
			if err != nil {
				return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
			}
			defer k1f.Close()
			_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
			if err != nil {
				return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
			}
			var keyC entries.KeyCache
			nRatchet := NRatchetTest
			roff := uint64(0)
			keyC.Drop()
			b := []byte{'a', 'b', 'c', 'd', 'e'}
			for i := uint64(0); i < NRounds*nRatchet; i++ {
				_, err := ul.Write(b)
				if err != nil {
					return fmt.Errorf("writing to user file: %s", err), 0
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
					return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
				}
				be, err := entry.MarshalBinary()
				if err != nil {
					return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
				}
				if in&0x80 != 0 {
					istamper = true
					be[int(in)%len(be)] = ^be[int(in)%len(be)]
				}
				_, err = lf.Write(be)
				if err != nil {
					return fmt.Errorf("writing to sealfs log: %s", err), 0
				}
				roff++
			}
			return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
		}
		err := testlog(t, filllog)
		if err == nil && istamper {
			t.Errorf("should not have verified, tampered")
		}
		if err != nil && !istamper {
			t.Errorf("should have verified, not tampered")
		}
	})
}

func FuzzTamperLog(f *testing.F) {
	for _, seed := range []byte{3, 4, 5, 0xff, 0xaa, 0xb, 0x10} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in byte) {
		istamper := false
		filllog := func(lfname string, d string, k1file string) (error, uint64) {
			userlogfile := fmt.Sprintf("%s/xxx", d)
			ul, err := os.Create(userlogfile)
			if err != nil {
				return fmt.Errorf("cannot create %s: %s\n", userlogfile, err), 0
			}
			defer ul.Close()
			inode, err := prepfiles.Inode(userlogfile)
			if err != nil {
				return fmt.Errorf("cannot find inode for %s: %s\n", userlogfile, err), 0
			}
			lf, err := os.OpenFile(lfname, os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("cannot open %s: %s\n", lfname, err), 0
			}
			defer lf.Close()
			_, err = lf.Seek(headers.SizeofLogfileHeader, io.SeekStart)
			if err != nil {
				return fmt.Errorf("cannot seek %s: %s\n", lfname, err), 0
			}
			k1f, err := os.Open(k1file)
			if err != nil {
				return fmt.Errorf("cannot open %s: %s\n", k1file, err), 0
			}
			defer k1f.Close()
			_, err = k1f.Seek(headers.SizeofKeyfileHeader, io.SeekStart)
			if err != nil {
				return fmt.Errorf("cannot seek %s: %s\n", k1file, err), 0
			}
			var keyC entries.KeyCache
			nRatchet := NRatchetTest
			roff := uint64(0)
			keyC.Drop()
			b := []byte{'a', 'b', 'c', 'd', 'e'}
			for i := uint64(0); i < NRounds*nRatchet; i++ {
				_, err := ul.Write(b)
				if err != nil {
					return fmt.Errorf("writing to user file: %s", err), 0
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
					return fmt.Errorf("cannot remac entry %s: %s\n", entry, err), 0
				}
				be, err := entry.MarshalBinary()
				if err != nil {
					return fmt.Errorf("cannot marshal entry %s: %s\n", entry, err), 0
				}
				if in&0x80 != 0 {
					istamper = true
					be[int(in)%len(be)] = ^be[int(in)%len(be)]
				}
				_, err = lf.Write(be)
				if err != nil {
					return fmt.Errorf("writing to sealfs log: %s", err), 0
				}
				roff++
				if in&0x80 == 0 {
					continue
				}
				istamper = true
				_, err = ul.Seek(int64(-len(b)), io.SeekCurrent)
				if err != nil {
					return fmt.Errorf("seeking user file: %s", err), 0
				}
				b[int(in)%len(b)] = ^b[int(in)%len(b)]
				_, err = ul.Write(b)
				if err != nil {
					return fmt.Errorf("writing to user file: %s", err), 0
				}
			}
			return nil, headers.SizeofKeyfileHeader + NRounds*entries.FprSize
		}
		err := testlog(t, filllog)
		if err == nil && istamper {
			t.Errorf("should not have verified, tampered")
		}
		if err != nil && !istamper {
			t.Errorf("should have verified, not tampered")
		}
	})
}
