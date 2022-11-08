package entries

import (
	"crypto/sha256"
	"fmt"
	"io"
	"bufio"
	"encoding/binary"
	"errors"
	"crypto/hmac"
	"os"
)

//TODO: color for logs

var (
	DebugKeyCache = false
	DebugEntries = false
)

func dprintf(isdebug bool, format string, a ...any) (n int, err error) {
	if !isdebug {
		return
	}
	return fmt.Fprintf(os.Stderr, format, a...)
}


const FprSize = sha256.Size

//see sealfstypes.h must match
type LogfileEntry struct {
	RatchetOffset uint64	//ratchet offset n of entries %NRATCHET
	Inode	uint64
	FileOffset	uint64
	WriteCount	uint64
	KeyFileOffset	uint64
	fpr [FprSize] uint8
}
const sizeofEntry = 5*8+FprSize

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
	ReadEntry(nRatchet uint64) (err error, entry *LogfileEntry)
}

type EntryFile struct {
	r io.Reader
	br *bufio.Reader
}

func NewEntryFile(r io.Reader) (entry *EntryFile) {
	entry = &EntryFile{r, bufio.NewReader(r)}
	return entry
}

func (eFile *EntryFile) ReadEntry(nRatchet uint64) (err error, entry *LogfileEntry) {
	var entryBuf[sizeofEntry] uint8
	n, err := io.ReadFull(eFile.br, entryBuf[:])
	if err != nil {
		return err, nil
	}
	if n != sizeofEntry {
		return errors.New("bad entry"), nil
	}
	entry = &LogfileEntry{}
	off := 0
	entry.RatchetOffset = binary.LittleEndian.Uint64(entryBuf[off:8+off])
	off += 8
	entry.Inode = binary.LittleEndian.Uint64(entryBuf[off:8+off])
	off += 8
	entry.FileOffset = binary.LittleEndian.Uint64(entryBuf[off:8+off])
	off += 8
	entry.WriteCount = binary.LittleEndian.Uint64(entryBuf[off:8+off])
	off += 8
	entry.KeyFileOffset = binary.LittleEndian.Uint64(entryBuf[off:8+off])
	off += 8
	copy(entry.fpr[:], entryBuf[off:off+FprSize])
	dprintf(DebugEntries, "ReadEntry: %s\n", entry)
	return nil, entry
}

const (
	LogNone = iota + 1
	LogText
	LogColor
	LogSilent
)

const (
	ColGreen = "\x1b[32m"
	ColRed = "\x1b[31m"
	ColEnd = "\x1b[0m"
)

const MaxWriteCount = 10*1024*1024	//10M

//TODO, color log
func (entry *LogfileEntry) DumpLog(logR io.ReadSeeker, isOk bool, typeLog int) (err error) {
	if entry.WriteCount > MaxWriteCount {
		return fmt.Errorf("too big a write for a single entry: %d\n", entry.WriteCount)
	}
	if typeLog == LogNone || typeLog == LogSilent {
		return nil
	}
	var currPos int64
	currPos, err = logR.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if currPos != int64(entry.FileOffset) {
		defer func () {
			_, err = logR.Seek(currPos, io.SeekStart)
		}()
		_, err = logR.Seek(int64(entry.FileOffset), io.SeekStart)
		if err != nil {
			return err
		}
	}
	br := bufio.NewReader(logR)
	nRead := uint64(0)
	for entry.WriteCount - nRead >= 0 {
		line, err := br.ReadString('\n');
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
		
		if typeLog == LogColor {
			ok = ColGreen+ok
			bad = ColRed+bad
			end = ColEnd
		}
		if isOk {
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

func (entry *LogfileEntry) makeHMAC(logR io.ReadSeeker, key []uint8) (err error, h []uint8) {
	dprintf(DebugKeyCache,"Verifying key[%d] %x\n", entry.KeyFileOffset, key[:])
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
		pos int64
	)
	currPos, err = logR.Seek(0, io.SeekCurrent)
	if err != nil {
		return err, nil
	}
	if currPos != int64(entry.FileOffset) {
		defer func () {
			_, errx := logR.Seek(currPos, io.SeekStart)
			if errx != nil {
				err = errx
			}
		}()
		pos, err = logR.Seek(int64(entry.FileOffset), io.SeekStart)
		if err != nil {
			return err, nil
		}
	}
	dprintf(DebugKeyCache, "LogR currPos %d pos %d\n", currPos, pos)
	
	br := bufio.NewReader(logR)
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

func ratchetKey(key []uint8, RatchetOffset uint64, nRatchet uint64) {
	dprintf(DebugKeyCache, "Ratchetkey {roff: %d, nr:%d}\n", RatchetOffset, nRatchet)
	dprintf(DebugKeyCache,"ratchetKey old key %x\n", key)
	mac := hmac.New(sha256.New, key)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, RatchetOffset)
	mac.Write(b)
	binary.LittleEndian.PutUint64(b, nRatchet)
	mac.Write(b)
	key = key[:0]
	mac.Sum(key)
	key = key[:mac.Size()]
	dprintf(DebugKeyCache, "ratchetKey new key %x\n", key)
}

type KeyCache struct {
	lastRatchetOffset uint64
	lastKeyOffset uint64
	key [FprSize]uint8
}

const InvalOff = 0xffffffffffffffff

func (keyC *KeyCache) String() string{
	
	s := fmt.Sprintf("keyc:[lastroff: %d", keyC.lastRatchetOffset);
	s += fmt.Sprintf(" lastkeyoff: %d, key: %x]", keyC.lastKeyOffset, keyC.key);
	return s
}

func (keyC *KeyCache) Drop() {
	dprintf(DebugKeyCache, "Drop\n")
	*keyC = KeyCache{lastRatchetOffset: InvalOff, lastKeyOffset: InvalOff}
}

func (keyC *KeyCache) isReKey(entry *LogfileEntry) bool {
	if keyC.lastKeyOffset == InvalOff || entry.RatchetOffset == 0 {
		return true
	}
	return  keyC.lastKeyOffset != entry.KeyFileOffset || keyC.lastRatchetOffset > entry.RatchetOffset
}

func (keyC *KeyCache) loadKey(entry *LogfileEntry, keyR io.ReadSeeker) (err error) {
	var currPos int64

	dprintf(DebugKeyCache, "Loadkey %d\n", entry.KeyFileOffset)
	currPos, err = keyR.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	defer func () {
		_, errx := keyR.Seek(currPos, io.SeekStart)
		if errx != nil {
			err = errx
		}
	}()
	_, err = keyR.Seek(int64(entry.KeyFileOffset), io.SeekStart)
	if err != nil {
		return err
	}
	//I am not using buffer (is it worth)?
	_, err = io.ReadFull(keyR, keyC.key[:])
	if err != nil {
		return err
	}
	keyC.lastKeyOffset = entry.KeyFileOffset
	keyC.lastRatchetOffset = 0
	dprintf(DebugKeyCache, "Loadkey key[%d] %x\n", entry.KeyFileOffset, keyC.key[:])
	return nil
}

func (keyC *KeyCache) ratchet(entry *LogfileEntry, nRatchet uint64) {
	dprintf(DebugKeyCache, "Ratchet {nr:%d} %d -> %d\n", nRatchet, keyC.lastRatchetOffset, entry.RatchetOffset)
	for i := keyC.lastRatchetOffset; i < entry.RatchetOffset; i++ {
		ratchetKey(keyC.key[:], i+1, nRatchet)
	}
	keyC.lastRatchetOffset = entry.RatchetOffset
}

func (keyC *KeyCache) Update(entry *LogfileEntry, keyR io.ReadSeeker, nRatchet uint64) (err error) {
	if nRatchet == 0 {
		return errors.New("cannot happen")
	}
	dprintf(DebugKeyCache, "Update {nr %d} %s\n", nRatchet, entry)
	if keyC.isReKey(entry) {
		if err := keyC.loadKey(entry, keyR); err != nil {
			return err
		}
		if nRatchet != 1 {
			ratchetKey(keyC.key[:], 0, nRatchet)
		}
	}
	keyC.ratchet(entry, nRatchet)
	return nil
}

func (entry *LogfileEntry) IsOk(logR io.ReadSeeker, keyR io.ReadSeeker, keyC *KeyCache, nRatchet uint64) bool {
	var err error
	var h []uint8
	if entry.RatchetOffset > nRatchet || entry.WriteCount > MaxWriteCount {
		return false
	}
	if err = keyC.Update(entry, keyR, nRatchet); err != nil {
		return false
	}
	if err, h = entry.makeHMAC(logR, keyC.key[:]); err != nil {
		return false
	}
	return hmac.Equal(h, entry.fpr[:])
}

const MaxNRatchet = 512

func (entry *LogfileEntry) NRatchetDetect(logR io.ReadSeeker, keyR io.ReadSeeker) (isOk bool, nRatchet uint64) {
	isOk = true

	var keyC KeyCache;
	keyC.Drop()
	if entry.IsOk(logR, keyR, &keyC, nRatchet) {
		return isOk, nRatchet
	}
	nRatchet = 1
	keyC.Drop()
	for !entry.IsOk(logR, keyR, &keyC, nRatchet) {
		if nRatchet++; nRatchet > MaxNRatchet {
			isOk = false
			break
		}
		keyC.Drop()	//different nRatchet means drop (first ratchet includes nRatchet)
	}
	return isOk, nRatchet
}