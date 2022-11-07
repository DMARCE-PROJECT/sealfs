package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/binheap"
	"sealfs/sealfs/entries"
	"strconv"
	"strings"
	"syscall"
	"golang.org/x/sys/unix"
)

const (
	MaxFiles           = 256
	DefaultLogfileName = ".SEALFS.LOG"
	NRatchetDefault    = uint64(1)
)

type OFile struct {
	heap   *heap.Heap[entries.LogfileEntry]
	inode  uint64
	file   *os.File
	offset uint64
}

func NewOfile(file *os.File, inode uint64) (o *OFile) {
	h := heap.NewHeap[entries.LogfileEntry](heap.Min)
	return &OFile{h, inode, file, 0}
}

func (o *OFile) String() string {
	return fmt.Sprintf("inode: %d fd: %v", o.inode, o.file)
}

type Rename struct {
	inode    uint64
	newInode uint64
}

func NewRename(inode uint64, newInode uint64) (rename *Rename) {
	return &Rename{inode, newInode}
}
func (r *Rename) String() (s string) {
	return fmt.Sprintf("%d -> %d\n", r.inode, r.newInode)
}

const ReadChunk = 256

type OFiles map[uint64]*OFile

// maps are indexed by inode
func scanDirFiles(path string, ofiles OFiles, renames Renames) (err error) {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	for fis, err := d.Readdir(ReadChunk); err == nil; fis, err = d.Readdir(ReadChunk) {
		for _, fi := range fis {
			if fi.Name()[0] == '.' {
				//ignore dots
				continue
			}
			switch {
			case fi.Mode().IsDir():
				npath := fmt.Sprintf("%s/%s", path, fi.Name())
				err = scanDirFiles(npath, ofiles, renames)
				if err != nil {
					return err
				}
			case fi.Mode().IsRegular():
				if fi.Name() == DefaultLogfileName {
					continue
				}
				stat, ok := fi.Sys().(*syscall.Stat_t)
				if !ok {
					return fmt.Errorf("Not a syscall.Stat_t %s", fi.Name())
				}
				fpath := fmt.Sprintf("%s/%s", path, fi.Name())
				file, err := os.Open(fpath)
				if err != nil {
					return err
				}
				ino := stat.Ino
				if r, isok := renames[ino]; isok {
					ino = r.newInode
				}
				o := NewOfile(file, ino)
				ofiles[ino] = o
			}
		}
	}
	return nil
}

const NBitsRatchet = 21

func unifyOffset(offset uint64, ratchetOffset uint64) uint64 {
	return (offset << NBitsRatchet) + ratchetOffset
}

func dumpHeap(heap *heap.Heap[entries.LogfileEntry]) {
	fmt.Fprintf(os.Stderr, "entries pending, [\n")
	for entry, min, ok := heap.Pop(); ok; entry, min, ok = heap.Pop() {
		off := unifyOffset(entry.FileOffset, entry.RatchetOffset)
		fmt.Fprintf(os.Stderr, "min: %d %d  offset: %d->", min, off, entry.FileOffset)
	}
	fmt.Fprintf(os.Stderr, "]\n")
}

func popContiguous(fileOffset *uint64, heap *heap.Heap[entries.LogfileEntry]) {
	for entry, min, ok := heap.Pop(); ok; entry, min, ok = heap.Pop() {
		if *fileOffset == entry.FileOffset {
			*fileOffset += entry.WriteCount
		} else {
			heap.Insert(min, entry)
			break
		}
	}
}

const MaxHeapSz = 2048

func advanceEntry(entry *entries.LogfileEntry, o *OFile) error {
	if o.offset == entry.FileOffset {
		o.offset += entry.WriteCount
		return nil
	}
	off := unifyOffset(entry.FileOffset, entry.RatchetOffset)
	o.heap.Insert(int(off), *entry)
	if o.heap.Len() > MaxHeapSz {
		return fmt.Errorf("read %d entries without fixing a jqueue\n", MaxHeapSz)
	}
	return nil
}

func checkTailOFiles(ofiles OFiles) error {
	for _, o := range ofiles {
		if o.heap != nil {
			popContiguous(&o.offset, o.heap)
		}
		if o.heap.Len() != 0 {
			dumpHeap(o.heap)
			return fmt.Errorf("disordered offsets pend for ofile inode: %d fd: %v\n\t", o.inode, o.file)
		}
	}
	return nil
}

func dumpOFiles(ofiles OFiles) error {
	fmt.Fprintf(os.Stderr, "Ofiles:\n")
	for _, o := range ofiles {
		fmt.Fprintf(os.Stderr, "ofile %s\n", o)
	}
	return nil
}

func isIncluded(n, a, b uint64) bool {
	return a <= n && n < b
}

//TODO: should check inode?
func isInRange(entry *entries.LogfileEntry, region Region) bool {
	begin, end := region.begin, region.end
	inr := isIncluded(begin, entry.FileOffset, entry.FileOffset+entry.WriteCount)
	inr = inr || isIncluded(end, entry.FileOffset, entry.FileOffset+entry.WriteCount)
	inr = inr || begin <= entry.FileOffset && entry.FileOffset+entry.WriteCount <= end
	return inr && entry.Inode == region.inode
}

const MaxNRatchet = 512

//inode == 0, check all files, else check only the inode
//begin == 0 && end == 0, check the whole file
//precondition:  begin <= end

const (
	sizeofKeyfileHeader = 8 + 8 //bytes
	sizeofLogfileHeader = 8     //bytes
)

type Region struct {
	inode uint64
	begin uint64
	end uint64
}

type Renames map[uint64]*Rename

type SealFsDesc struct {
	kf *os.File
	lf io.ReadCloser
	dirPath string
	typeLog int
}

func badOff(entry *entries.LogfileEntry, keyOff uint64, ratchetOffset uint64) {
	fmt.Fprintf(os.Stderr, "koffset %d or roff %d not correct: ", entry.KeyFileOffset, entry.RatchetOffset)
	fmt.Fprintf(os.Stderr, "should be %d %d", keyOff,  entry.RatchetOffset)
	fmt.Fprintf(os.Stderr, "%s\n", entry)
}

func badEntry(entry *entries.LogfileEntry, nRatchet uint64) {
	fmt.Fprintf(os.Stderr, "can't verify entry with nratchet %d: ", nRatchet)
	fmt.Fprintf(os.Stderr, "%s\n", entry)
}

func verify(sf *SealFsDesc, region Region, renames Renames, nRatchet uint64) error {
	var file *os.File
	var keyC entries.KeyCache
	keyC.Drop()
	gotNRatchet := false
	nBad := uint64(0)
	c := uint64(0)
	ratchetOffset := uint64(0)

	ofiles := make(map[uint64]*OFile)
	if err := scanDirFiles(sf.dirPath, ofiles, renames); err != nil {
		return fmt.Errorf("scanDirFiles %s", err)
	}
	if region.inode == 0 && sf.typeLog != entries.LogSilent {
		dumpOFiles(ofiles)
	}
	entryFile := entries.NewEntryFile(sf.lf)
	keyR := entries.NewBufReadSeeker(sf.kf)
	for {
		err, entry := entryFile.ReadEntry(nRatchet)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("can't read from lfile: %s\n", err)
		}
		o, ok := ofiles[entry.Inode]
		if !ok && entry.Inode != entries.FakeInode {
			return fmt.Errorf("file with inode %d not found!", entry.Inode)
		}
		file = nil
		if entry.Inode != entries.FakeInode {
			file = o.file
		}
		if !gotNRatchet {
			gotNRatchet, nRatchet = entry.NRatchetDetect(file, keyR)
			if !gotNRatchet {
				return fmt.Errorf("can't find a correct nratchet")
			}
			if sf.typeLog != entries.LogSilent {
				fmt.Fprintf(os.Stderr, "NRatchetDetect got nratchet %d\n", nRatchet)
			}
		}
		if entry.Inode != entries.FakeInode {
			if region.inode != 0 {
				if  region.end != 0 && !isInRange(entry, region) {
					continue
				}
				if o.offset == 0 {
					o.offset = region.begin
				}
			}
			err = advanceEntry(entry, o)
			if err != nil {
				return errors.New("can't order entries for entry")
			}
			popContiguous(&o.offset, o.heap)
		}
		isok := entry.IsOk(file, keyR, &keyC, nRatchet)
		if !isok {
			if sf.typeLog == entries.LogNone || sf.typeLog == entries.LogSilent {
				return errors.New("bad entry")
			}
			badEntry(entry, nRatchet)
			nBad++
		}
		if entry.Inode != entries.FakeInode {
			err = entry.DumpLog(file, isok, sf.typeLog)
			if err != nil {
				fmt.Fprintf(os.Stderr, "can't dump log entry %s", entry)
				return err
			}
			if region.inode != 0 && o.offset >= region.end {
				break
			}
		}
		keyOff := sizeofKeyfileHeader+(c/nRatchet)*entries.FprSize
		isWrongOff := entry.KeyFileOffset != keyOff || entry.RatchetOffset != ratchetOffset
		if region.inode == 0 &&  isWrongOff {
			badOff(entry, keyOff, ratchetOffset)
			return fmt.Errorf("incorrect koffset or roff")
		}
		c++
		ratchetOffset = (ratchetOffset + 1) % nRatchet
	}
	if region.inode == 0 && c%nRatchet != 0 {
		return fmt.Errorf("number of entries is not a multiple of nratchet: %d %d\n", c, nRatchet)
	}
	err := checkTailOFiles(ofiles)
	if err != nil {
		return fmt.Errorf("error, checkTailOFiles %s\n", err)
	}
	if c == 0 {
		return fmt.Errorf("error, no entries in the log\n")
	}
	if nBad != 0 {
		if sf.typeLog != entries.LogSilent {	
			fmt.Printf("error: %d entries verified, some bad logs: %d correct,  %d incorrect\n", c, c-nBad, nBad)
		}
		return errors.New("error: did not verify")
	}
	if sf.typeLog != entries.LogSilent {	
		fmt.Printf("%d entries verified, correct logs\n", c)
	}
	return nil
}

func readChunk(f *os.File, p []byte, pos uint64) (err error) {
	currPos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if currPos != int64(pos) {
		defer func() {
			_, err = f.Seek(currPos, io.SeekStart)
		}()
		_, err := f.Seek(int64(pos), io.SeekStart)
		if err != nil {
			return err
		}
	}
	_, err = io.ReadFull(f, p[:])
	if err != nil {
		return err
	}
	return nil
}

func checkKeyStreams(alphaF *os.File, betaF *os.File, burnt uint64) (err error) {
	var (
		prevalpha  [entries.FprSize]byte
		prevbeta   [entries.FprSize]byte
		postvalpha [entries.FprSize]byte
		postvbeta  [entries.FprSize]byte
	)
	fia, err := alphaF.Stat()
	if err != nil {
		return errors.New("can't stat alpha")
	}
	fib, err := betaF.Stat()
	if err != nil {
		return errors.New("can't stat beta")
	}
	if fia.Size() != fib.Size() {
		return errors.New("keystream size do not match")
	}
	if burnt > uint64(fia.Size()) {
		return errors.New("keystreams are too small")
	}
	if err := readChunk(alphaF, prevalpha[:], burnt-entries.FprSize); err != nil {
		return err
	}
	if err := readChunk(betaF, prevbeta[:], burnt-entries.FprSize); err != nil {
		return err
	}
	if prevalpha == prevbeta {
		return errors.New("keystreams are not valid: last burnt chunk is equal")
	}
	if burnt == uint64(fia.Size()) {
		fmt.Fprintf(os.Stderr, "alpha keystream is completely burnt\n")
		return
	}
	if err := readChunk(alphaF, postvalpha[:], burnt); err != nil {
		return err
	}
	if err := readChunk(betaF, postvbeta[:], burnt); err != nil {
		return err
	}
	if postvalpha != postvbeta {
		return errors.New("keystreams are wrong: first unburnt chunk is different")
	}
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "USAGE: verify dir kalpha kbeta [-D[e|k]] [-t | -T] [-n lfilename] [-i inode begin end] [-nfs0 nlog0 -nfs1 nlog1...] \n")
	os.Exit(2)
}

func InodeBegEnd(args []string) (region Region, err error) {
	var n int

	if len(args) != 3 {
		return region, errors.New("short inode descriptor")
	}
	n, err = strconv.Atoi(args[0])
	if err != nil {
		return region, err
	}
	region.inode = uint64(n)
	n, err = strconv.Atoi(args[1])
	if err != nil {
		return region, err
	}
	region.begin = uint64(n)
	n, err = strconv.Atoi(args[2])
	if err != nil {
		return region, err
	}
	region.end = uint64(n)
	return region, err
}

type KeyFileHeader struct {
	magic uint64
	burnt uint64
}

func (kh *KeyFileHeader) FillHeader(r io.Reader) (err error) {
	var khBuf [sizeofKeyfileHeader]uint8
	n, err := io.ReadFull(r, khBuf[:])
	if err != nil {
		return err
	}
	if n != sizeofKeyfileHeader {
		return errors.New("bad keyfile header")
	}
	kh.magic = binary.LittleEndian.Uint64(khBuf[0:8])
	kh.burnt = binary.LittleEndian.Uint64(khBuf[8:16])
	return nil
}

type LogFileHeader struct {
	magic uint64
}

func (lf *LogFileHeader) FillHeader(r io.Reader) (err error) {
	var lfBuf [sizeofLogfileHeader]uint8
	n, err := io.ReadFull(r, lfBuf[:])
	if err != nil {
		return err
	}
	if n != sizeofLogfileHeader {
		return errors.New("bad logfile header")
	}
	lf.magic = binary.LittleEndian.Uint64(lfBuf[0:8])
	return nil
}

func isatty(file *os.File) bool {
	fd := file.Fd()
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

func setDebugs(d rune) {
	switch d {
	case 'e':
		entries.DebugEntries = true
	case 'k':
		entries.DebugKeyCache = true
	}
}

func main() {
	var err error
	renames := make(Renames)
	nRatchet := NRatchetDefault
	region := Region{uint64(0), uint64(0), uint64(0)}
	lname := DefaultLogfileName
	if len(os.Args) < 3 {
		usage()
	}
	typeLog := entries.LogNone
	dir := os.Args[1]
	kalpha := os.Args[2]
	kbeta := os.Args[3]
	args := os.Args[4:]
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			usage()
		}
		if len(args[i]) < 2 {
			usage()
		}
		switch args[i][1] {
		case 'D':
			if len(args[i]) < 3 {
				usage()
			}
			setDebugs(rune(args[i][2]))
		case 'i':
			r0 := Region{0, 0, 0}
			if len(args[i:]) < 3 || region != r0 {
				usage()
			}
			region, err = InodeBegEnd(args[i+1 : i+4])
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot parse inode number %s", err)
				usage()
			}
			i += 3
		case 't':
			typeLog = entries.LogText
			if isatty(os.Stdout) {
				typeLog = entries.LogColor
			}
		case 'T':
			typeLog = entries.LogText
		default:
			if len(args[i]) < 2 || len(args[i:]) < 2 {
				usage()
			}
			oi, err := strconv.Atoi(args[i][1:])
			if err != nil {
				usage()
			}
			ni, err := strconv.Atoi(args[i+1])
			if err != nil {
				usage()
			}
			r := NewRename(uint64(oi), uint64(ni))
			renames[r.inode] = r
			i++
		}
	}
	lpath := fmt.Sprintf("%s/%s", dir, lname)
	alphaf, err := os.Open(kalpha)
	if err != nil {
		log.Fatalf("can't open %s\n", kalpha)
	}
	defer alphaf.Close()
	betaf, err := os.Open(kbeta)
	if err != nil {
		log.Fatalf("can't open %s", kbeta)
	}
	defer betaf.Close()
	lf, err := os.Open(lpath)
	if err != nil {
		log.Fatalf("can't open %s", lpath)
	}
	fmt.Fprintf(os.Stderr, "lf %s\n", lpath)
	defer lf.Close()

	kalphaHeader := &KeyFileHeader{}
	err = kalphaHeader.FillHeader(alphaf)
	if err != nil {
		log.Fatal("can't read kalphahdr")
	}
	kbetaHeader := &KeyFileHeader{}
	err = kbetaHeader.FillHeader(betaf)
	if err != nil {
		log.Fatal("can't read kbetahdr")
	}
	logHeader := &LogFileHeader{}
	err = logHeader.FillHeader(lf)
	if err != nil {
		log.Fatal("can't read lheader")
	}
	if logHeader.magic != kalphaHeader.magic || logHeader.magic != kbetaHeader.magic {
		log.Fatal("magic numbers don't match")
	}
	fmt.Printf("k1 burnt: %d\n", kalphaHeader.burnt)
	err = checkKeyStreams(alphaf, betaf, kalphaHeader.burnt)
	if err != nil {
		log.Fatalf("checkkeystreams: %s", err)
	}
	for _, r := range renames {
		fmt.Fprintf(os.Stderr, "rename inode %s\n", r)
	}
	desc := &SealFsDesc{kf: betaf, lf: lf, dirPath: dir, typeLog: typeLog}
	err = verify(desc, region, renames, nRatchet)
	if err != nil {
		log.Fatal(err)
	}
	if region.inode != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: you SHOULD run a"+
			" complete verification"+
			" to probe that the file has not been truncated\n")
	}
	os.Exit(0)
}
