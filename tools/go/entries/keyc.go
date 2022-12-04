package entries

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	DebugKeyCache = false
)

func ratchetKey(key []uint8, RatchetOffset uint64, nRatchet uint64) {
	dprintf(DebugKeyCache, "Ratchetkey {roff: %d, nr:%d}\n", RatchetOffset, nRatchet)
	dprintf(DebugKeyCache, "ratchetKey old key %x\n", key)
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
	lastKeyOffset     uint64
	Key               [FprSize]uint8
}

func (keyC *KeyCache) String() string {

	s := fmt.Sprintf("keyc:[lastroff: %d", keyC.lastRatchetOffset)
	s += fmt.Sprintf(" lastkeyoff: %d, key: %x]", keyC.lastKeyOffset, keyC.Key)
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
	return keyC.lastKeyOffset != entry.KeyFileOffset || keyC.lastRatchetOffset > entry.RatchetOffset
}

func (keyC *KeyCache) loadKey(entry *LogfileEntry, keyR io.ReadSeeker) (err error) {
	var currPos int64

	dprintf(DebugKeyCache, "Loadkey %d\n", entry.KeyFileOffset)
	currPos, err = keyR.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	defer func() {
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
	_, err = io.ReadFull(keyR, keyC.Key[:])
	if err != nil {
		return err
	}
	keyC.lastKeyOffset = entry.KeyFileOffset
	keyC.lastRatchetOffset = 0
	dprintf(DebugKeyCache, "Loadkey key[%d] %x\n", entry.KeyFileOffset, keyC.Key[:])
	return nil
}

func (keyC *KeyCache) ratchet(entry *LogfileEntry, nRatchet uint64) {
	dprintf(DebugKeyCache, "Ratchet {nr:%d} %d -> %d\n", nRatchet, keyC.lastRatchetOffset, entry.RatchetOffset)
	for i := keyC.lastRatchetOffset; i < entry.RatchetOffset; i++ {
		ratchetKey(keyC.Key[:], i+1, nRatchet)
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
			ratchetKey(keyC.Key[:], 0, nRatchet)
		}
	}
	keyC.ratchet(entry, nRatchet)
	return nil
}
