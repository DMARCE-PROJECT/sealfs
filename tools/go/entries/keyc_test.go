package entries_test

import (
	"io"
	"sealfs/sealfs/entries"
	"testing"
)

type CountReadSeeker struct {
	nread uint64
	off   int64
}

func (crs *CountReadSeeker) Read(p []byte) (n int, err error) {
	p = make([]byte, len(p))
	crs.nread++
	return len(p), nil
}

func (crs *CountReadSeeker) Seek(offset int64, whence int) (noffset int64, err error) {
	switch whence {
	case io.SeekStart:
		crs.off = offset
	case io.SeekCurrent:
		crs.off += offset
		if crs.off < 0 {
			panic("offset should not be negative")
		}
	}
	return crs.off, nil
}

const (
	MaxNRatchetTest = uint64(20)
	NRounds         = uint64(3)
	KeyOffStart     = entries.FprSize
	KeyOff          = 12 * entries.FprSize
)

func TestKeyCacheRatchetOff(t *testing.T) {
	var keyC entries.KeyCache
	entry := &entries.LogfileEntry{}
	crs := &CountReadSeeker{}
	crs.Seek(KeyOffStart, io.SeekCurrent)
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		crs.nread = 0
		for roff := uint64(0); roff < NRounds*nRatchet; roff++ {
			entry.KeyFileOffset = KeyOff
			entry.RatchetOffset = roff % nRatchet
			keyC.Update(entry, crs, nRatchet)
		}
		if crs.off != KeyOffStart {
			t.Errorf("keystream wrong offset %d != %d", crs.off, KeyOff)
		}
		if crs.nread != NRounds {
			t.Errorf("keycache updates number wrong %d != %d", crs.nread, NRounds)
		}
	}
}

func TestKeyCacheRatchetOffDown(t *testing.T) {
	var keyC entries.KeyCache
	entry := &entries.LogfileEntry{}
	crs := &CountReadSeeker{}
	crs.Seek(KeyOffStart, io.SeekCurrent)
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		crs.nread = 0
		for roff := int(nRatchet) - 1; roff > 0; roff-- {
			entry.KeyFileOffset = KeyOff
			entry.RatchetOffset = uint64(roff) % nRatchet
			keyC.Update(entry, crs, nRatchet)
		}
		if crs.off != KeyOffStart {
			t.Errorf("keystream wrong offset %d != %d", crs.off, KeyOff)
		}
		if crs.nread != nRatchet-1 {
			t.Errorf("keycache updates number wrong %d != %d", crs.nread, nRatchet-1)
		}
	}
}

func TestKeyCacheKeyOff(t *testing.T) {
	var keyC entries.KeyCache
	entry := &entries.LogfileEntry{}
	crs := &CountReadSeeker{}
	for nRatchet := uint64(1); nRatchet < MaxNRatchetTest; nRatchet++ {
		keyC.Drop()
		crs.nread = 0
		for keycnt := uint64(0); keycnt < NRounds; keycnt++ {
			entry.RatchetOffset = nRatchet / 2
			entry.KeyFileOffset = keycnt * entries.FprSize
			keyC.Update(entry, crs, nRatchet)
		}
		if crs.nread != NRounds {
			t.Errorf("keycache updates number wrong %d != %d", crs.nread, NRounds)
		}
	}
}
