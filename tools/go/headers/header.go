package headers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	SizeofLogfileHeader = 8     //bytes
	SizeofKeyfileHeader = 8 + 8 //bytes
)

type LogFileHeader struct {
	Magic uint64
}

func (lf *LogFileHeader) MarshalBinary() (data []byte, err error) {
	var b [SizeofLogfileHeader]byte
	binary.LittleEndian.PutUint64(b[:], lf.Magic)
	return b[:], nil
}

func (lf *LogFileHeader) UnMarshalBinary(data []byte) (err error) {
	if len(data) < SizeofLogfileHeader {
		return fmt.Errorf("data too small for logfile header %s\n", err)
	}
	lf.Magic = binary.LittleEndian.Uint64(data)
	return nil
}

func (lf *LogFileHeader) FillHeader(r io.Reader) (err error) {
	var lfBuf [SizeofLogfileHeader]byte
	n, err := io.ReadFull(r, lfBuf[:])
	if err != nil {
		return err
	}
	if n != SizeofLogfileHeader {
		return errors.New("bad logfile header")
	}
	return lf.UnMarshalBinary(lfBuf[:])
}

func (lf *LogFileHeader) WriteHeader(w io.Writer) (err error) {
	b, err := lf.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal key header %s", err)
	}
	_, err = w.Write(b)
	return err
}

type KeyFileHeader struct {
	Magic uint64
	Burnt uint64
}

func (kh *KeyFileHeader) MarshalBinary() (data []byte, err error) {
	var b [SizeofKeyfileHeader]byte
	binary.LittleEndian.PutUint64(b[0:8], kh.Magic)
	binary.LittleEndian.PutUint64(b[8:16], kh.Burnt)
	return b[:], nil
}

func (kh *KeyFileHeader) UnMarshalBinary(data []byte) (err error) {
	if len(data) < SizeofKeyfileHeader {
		return fmt.Errorf("data too small for logfile header %s\n", err)
	}
	kh.Magic = binary.LittleEndian.Uint64(data[0:8])
	kh.Burnt = binary.LittleEndian.Uint64(data[8:16])
	return nil
}

func (kh *KeyFileHeader) FillHeader(r io.Reader) (err error) {
	var khBuf [SizeofKeyfileHeader]byte
	n, err := io.ReadFull(r, khBuf[:])
	if err != nil {
		return err
	}
	if n != SizeofKeyfileHeader {
		return errors.New("bad keyfile header")
	}
	return kh.UnMarshalBinary(khBuf[:])
	return nil
}

func (kh *KeyFileHeader) WriteHeader(w io.Writer) (err error) {
	b, err := kh.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal key header %s", err)
	}
	_, err = w.Write(b)
	return err
}
