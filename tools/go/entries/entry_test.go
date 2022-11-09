package entries_test

import (
	"io"
	"sealfs/sealfs/entries"
	"testing"
	"encoding/binary"
	"errors"
)

type KeyReadSeeker struct {
	nread uint64
	off   int64
}

//fakes a different unique key per offset, otherwise, it is just
// a read seeker.
func (krs *KeyReadSeeker) Read(p []byte) (n int, err error) {
	if len(p) < 8 {
		return -1, errors.New("small read for key")
	}
	for i, _ := range(p) {
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
	logrs := &KeyReadSeeker{}	//it fakes a file good enough
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		for roff := uint64(0); roff < NRounds*nRatchet; roff++ {
			entry.KeyFileOffset = entries.SizeofKeyfileHeader + (roff/nRatchet)*entries.FprSize
			entry.RatchetOffset = roff % nRatchet
			entry.ReMac(logrs, krs, &keyC, nRatchet)
			if !entry.IsOk(logrs, krs, &keyC, nRatchet) {
				t.Errorf("entry is not ok %s\n", entry)
			}
			
		}
	}
}
