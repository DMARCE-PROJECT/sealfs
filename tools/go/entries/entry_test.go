package entries_test

import (
	"encoding/binary"
	"errors"
	"io"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/headers"
	"testing"
)

type KeyReadSeeker struct {
	nread uint64
	off   int64
}

// fakes a different unique key per offset, otherwise, it is just
// a read seeker.
func (krs *KeyReadSeeker) Read(p []byte) (n int, err error) {
	if len(p) < 8 {
		return -1, errors.New("small read for key")
	}
	for i, _ := range p {
		p[i] = 0
	}
	binary.LittleEndian.PutUint64(p, uint64(krs.off))
	krs.nread++
	return len(p), nil
}

func (krs *KeyReadSeeker) Seek(offset int64, whence int) (noffset int64, err error) {
	switch whence {
	case io.SeekStart:
		krs.off = offset
	case io.SeekCurrent:
		krs.off += offset
		if krs.off < 0 {
			panic("offset should not be negative")
		}
	}
	return krs.off, nil
}

func TestEntry(t *testing.T) {
	var keyC entries.KeyCache
	entry := &entries.LogfileEntry{}
	krs := &KeyReadSeeker{}
	logrs := &KeyReadSeeker{} //it fakes a file good enough
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		for roff := uint64(0); roff < NRounds*nRatchet; roff++ {
			entry.KeyFileOffset = headers.SizeofKeyfileHeader + (roff/nRatchet)*entries.FprSize
			entry.RatchetOffset = roff % nRatchet
			entry.ReMac(logrs, krs, &keyC, nRatchet)
			if !entry.IsOk(logrs, krs, &keyC, nRatchet) {
				t.Errorf("entry is not ok %s\n", entry)
			}

		}
	}
}

func TestEntryMarshal(t *testing.T) {
	var keyC entries.KeyCache
	entry := &entries.LogfileEntry{}
	krs := &KeyReadSeeker{}
	logrs := &KeyReadSeeker{} //it fakes a file good enough
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		for roff := uint64(0); roff < NRounds*nRatchet; roff++ {
			//make up some totally false values
			entry.Inode = roff / 2
			entry.FileOffset = roff * 3
			entry.WriteCount = roff * 5

			//make up some correct values
			entry.KeyFileOffset = headers.SizeofKeyfileHeader + (roff/nRatchet)*entries.FprSize
			entry.RatchetOffset = roff % nRatchet
			entry.ReMac(logrs, krs, &keyC, nRatchet)
			b, err := entry.MarshalBinary()
			if err != nil {
				t.Errorf("cannot marshal entry %s: %s\n", entry, err)
			}
			e2 := &entries.LogfileEntry{}
			err = e2.UnMarshalBinary(b)
			if err != nil {
				t.Errorf("cannot unmarshal entry %s: %s\n", entry, err)
			}
			if *entry != *e2 {
				t.Errorf("entries before and after marshal are different: \n\t%s\n\t%s\n", entry, e2)
			}
			//make sure comparison is alright and includes hmac
			e2.Inode = 1 ^ e2.Inode
			e2.ReMac(logrs, krs, &keyC, nRatchet)
			e2.Inode = entry.Inode
			if *entry == *e2 {
				t.Errorf("entries after modification and remac should be different: \n\t%s\n\t%s\n", entry, e2)
			}

		}
	}
}
