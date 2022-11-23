package entries

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	DebugEntries = false
)

const (
	SizeofEntry = 5*8 + FprSize
	FprSize     = sha256.Size
	InvalOff    = ^uint64(0)
)

func dprintf(isdebug bool, format string, a ...any) (n int, err error) {
	if !isdebug {
		return
	}
	return fmt.Fprintf(os.Stderr, format, a...)
}

// see sealfstypes.h must match
type LogfileEntry struct {
	RatchetOffset uint64 //ratchet offset n of entries %NRATCHET
	Inode         uint64
	FileOffset    uint64
	WriteCount    uint64
	KeyFileOffset uint64
	fpr           [FprSize]uint8
}

func (entry *LogfileEntry) String() string {
	s := fmt.Sprintf("[ratchetoffset: %d ", entry.RatchetOffset)
	if entry.Inode == FakeInode {
		s += fmt.Sprintf("Inode: %s offset: %d ", "SEAL", entry.FileOffset)
	} else {
		s += fmt.Sprintf("Inode: %d offset: %d ", entry.Inode, entry.FileOffset)
	}
	s += fmt.Sprintf("count: %d koffset: %d]", entry.WriteCount, entry.KeyFileOffset)
	return s
}

type EntryReader interface {
	ReadEntry() (err error, entry *LogfileEntry)
}

type EntryFile struct {
	r  io.Reader
	br *bufio.Reader
}

func NewEntryFile(r io.Reader) (entry *EntryFile) {
	entry = &EntryFile{r, bufio.NewReader(r)}
	return entry
}

func (entry *LogfileEntry) MarshalBinary() (data []byte, err error) {
	var b [SizeofEntry]byte
	off := 0
	binary.LittleEndian.PutUint64(b[off:8+off], entry.RatchetOffset)
	off += 8
	binary.LittleEndian.PutUint64(b[off:8+off], entry.Inode)
	off += 8
	binary.LittleEndian.PutUint64(b[off:8+off], entry.FileOffset)
	off += 8
	binary.LittleEndian.PutUint64(b[off:8+off], entry.WriteCount)
	off += 8
	binary.LittleEndian.PutUint64(b[off:8+off], entry.KeyFileOffset)
	off += 8
	copy(b[off:off+FprSize], entry.fpr[:])
	return b[:], nil
}
func (entry *LogfileEntry) UnMarshalBinary(data []byte) (err error) {
	if len(data) < SizeofEntry {
		return fmt.Errorf("data too small for entry %s\n", err)
	}
	off := 0
	entry.RatchetOffset = binary.LittleEndian.Uint64(data[off : 8+off])
	off += 8
	entry.Inode = binary.LittleEndian.Uint64(data[off : 8+off])
	off += 8
	entry.FileOffset = binary.LittleEndian.Uint64(data[off : 8+off])
	off += 8
	entry.WriteCount = binary.LittleEndian.Uint64(data[off : 8+off])
	off += 8
	entry.KeyFileOffset = binary.LittleEndian.Uint64(data[off : 8+off])
	off += 8
	copy(entry.fpr[:], data[off:off+FprSize])
	return nil
}

func (eFile *EntryFile) ReadEntry() (err error, entry *LogfileEntry) {
	var entryBuf [SizeofEntry]uint8
	n, err := io.ReadFull(eFile.br, entryBuf[:])
	if err != nil {
		return err, nil
	}
	if n != SizeofEntry {
		return errors.New("bad entry"), nil
	}
	entry = &LogfileEntry{}
	err = entry.UnMarshalBinary(entryBuf[:])
	if err != nil {
		return err, nil
	}

	dprintf(DebugEntries, "ReadEntry: %s\n", entry)
	return nil, entry
}

const (
	LogNone = iota + 1
	LogText
	LogColText
	LogSilent
)

const (
	ColGreen = "\x1b[32m"
	ColRed   = "\x1b[31m"
	ColEnd   = "\x1b[0m"
)

const MaxWriteCount = 10 * 1024 * 1024 //10M

// TODO, color log
func (entry *LogfileEntry) DumpLog(logr io.ReadSeeker, isok bool, typelog int) (err error) {
	if entry.WriteCount > MaxWriteCount {
		return fmt.Errorf("too big a write for a single entry: %d\n", entry.WriteCount)
	}
	if typelog == LogNone || typelog == LogSilent {
		return nil
	}
	var currPos int64
	currPos, err = logr.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if currPos != int64(entry.FileOffset) {
		defer func() {
			_, err = logr.Seek(currPos, io.SeekStart)
		}()
		_, err = logr.Seek(int64(entry.FileOffset), io.SeekStart)
		if err != nil {
			return err
		}
	}
	br := bufio.NewReader(logr)
	nRead := uint64(0)
	for entry.WriteCount-nRead >= 0 {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		if len(line) == 0 {
			break
		}
		nRead += uint64(len(line))
		//may break UTF, we convert to string to redecode
		line = string(line[0:entry.WriteCount])

		ok := "[OK] "
		bad := "[BAD] "
		end := ""

		if typelog == LogColText {
			ok = ColGreen + ok
			bad = ColRed + bad
			end = ColEnd
		}
		if isok {
			fmt.Printf("%s%d:%s %s\n", ok, entry.Inode, end, line)
		} else {
			fmt.Printf("%s%d:%s %s\n", bad, entry.Inode, end, line)
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

const FakeInode = ^uint64(0)

func (entry *LogfileEntry) makeHMAC(logr io.ReadSeeker, key []uint8) (err error, h []uint8) {
	dprintf(DebugEntries, "Verifying key[%d] %x\n", entry.KeyFileOffset, key[:])
	if entry.WriteCount > MaxWriteCount {
		return fmt.Errorf("too big a write for a single entry: %d\n", entry.WriteCount), nil
	}
	b := make([]byte, 8)
	mac := hmac.New(sha256.New, key)
	binary.LittleEndian.PutUint64(b, entry.RatchetOffset)
	mac.Write(b)
	binary.LittleEndian.PutUint64(b, entry.Inode)
	mac.Write(b)
	binary.LittleEndian.PutUint64(b, entry.FileOffset)
	mac.Write(b)
	binary.LittleEndian.PutUint64(b, entry.WriteCount)
	mac.Write(b)
	binary.LittleEndian.PutUint64(b, entry.KeyFileOffset)
	mac.Write(b)

	if entry.Inode == FakeInode {
		h = mac.Sum(nil)
		return nil, h
	}
	var (
		currPos int64
		pos     int64
	)
	currPos, err = logr.Seek(0, io.SeekCurrent)
	if err != nil {
		return err, nil
	}
	if currPos != int64(entry.FileOffset) {
		defer func() {
			_, errx := logr.Seek(currPos, io.SeekStart)
			if errx != nil {
				err = errx
			}
		}()
		pos, err = logr.Seek(int64(entry.FileOffset), io.SeekStart)
		if err != nil {
			return err, nil
		}
	}
	dprintf(DebugEntries, "LogR currPos %d pos %d\n", currPos, pos)

	br := bufio.NewReader(logr)
	nw, err := io.CopyN(mac, br, int64(entry.WriteCount))
	if nw != int64(entry.WriteCount) {
		return fmt.Errorf("cannot read from file, %s, offset %d, entry.WriteCount %d\n", err, entry.FileOffset, entry.WriteCount), nil
	}
	if err == io.EOF {
		return fmt.Errorf("cannot read from file, offset %d, premature EOF\n", entry.FileOffset), nil
	}
	if err != nil {
		return err, nil
	}
	h = mac.Sum(nil)
	return nil, h
}

func (entry *LogfileEntry) IsOk(logr io.ReadSeeker, keyr io.ReadSeeker, keyc *KeyCache, nratchet uint64) bool {
	var err error
	var h []uint8
	if entry.RatchetOffset > nratchet || entry.WriteCount > MaxWriteCount {
		return false
	}
	if err = keyc.Update(entry, keyr, nratchet); err != nil {
		return false
	}
	if err, h = entry.makeHMAC(logr, keyc.key[:]); err != nil {
		return false
	}
	return hmac.Equal(h, entry.fpr[:])
}

func (entry *LogfileEntry) ReMac(logr io.ReadSeeker, keyr io.ReadSeeker, keyc *KeyCache, nratchet uint64) error {
	var err error
	var h []uint8
	if entry.RatchetOffset > nratchet || entry.WriteCount > MaxWriteCount {
		return errors.New("bad entry")
	}
	if err = keyc.Update(entry, keyr, nratchet); err != nil {
		return fmt.Errorf("cannot obtain queue %s", err)
	}
	if err, h = entry.makeHMAC(logr, keyc.key[:]); err != nil {
		return fmt.Errorf("cannot make hmac %s", err)
	}
	copy(entry.fpr[:], h)
	return nil
}

const MaxNRatchet = 512

func (entry *LogfileEntry) NRatchetDetect(logr io.ReadSeeker, keyr io.ReadSeeker) (isok bool, nratchet uint64) {
	isok = true

	var keyc KeyCache
	keyc.Drop()
	if entry.IsOk(logr, keyr, &keyc, nratchet) {
		return isok, nratchet
	}
	nratchet = 1
	keyc.Drop()
	for !entry.IsOk(logr, keyr, &keyc, nratchet) {
		if nratchet++; nratchet > MaxNRatchet {
			isok = false
			break
		}
		keyc.Drop() //different nRatchet means drop (first ratchet includes nRatchet)
	}
	return isok, nratchet
}
