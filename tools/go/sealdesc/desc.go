package sealdesc

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sealfs/sealfs/binheap"
	"sealfs/sealfs/entries"
	"sealfs/sealfs/headers"
	"strconv"
	"syscall"
)

var (
	DebugJQueue = false	//only for debugging
)

const (
	MaxFiles           = 256
	DefaultLogfileName = ".SEALFS.LOG"
)

type OFile struct {
	heap   *heap.Heap[*entries.LogfileEntry]
	inode  uint64
	file   *os.File
	offset uint64
}

func dhprintf(format string, a ...any) (n int, err error) {
	if !DebugJQueue {
		return
	}
	return fmt.Fprintf(os.Stderr, format, a...)
}

func NewOfile(file *os.File, inode uint64) (o *OFile) {
	h := heap.NewHeap[*entries.LogfileEntry](heap.Min)
	return &OFile{h, inode, file, 0}
}

func (o *OFile) String() string {
	return fmt.Sprintf("inode: %d fd: %d", o.inode, o.file.Fd())
}

type Rename struct {
	Inode    uint64
	NewInode uint64
}

func NewRename(inode uint64, newinode uint64) (rename *Rename) {
	return &Rename{inode, newinode}
}
func (r *Rename) String() (s string) {
	return fmt.Sprintf("%d -> %d\n", r.Inode, r.NewInode)
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
					ino = r.NewInode
				}
				o := NewOfile(file, ino)
				ofiles[ino] = o
			}
		}
	}
	return nil
}

const NBitsRatchet = 21

func unifyOffset(offset uint64, ratchetoffset uint64) uint64 {
	return (offset << NBitsRatchet) + ratchetoffset
}

func dumpHeap(heap *heap.Heap[*entries.LogfileEntry]) {
	log.Printf("entries pending, [\n")
	for entry, min, ok := heap.Pop(); ok; entry, min, ok = heap.Pop() {
		off := unifyOffset(entry.FileOffset, entry.RatchetOffset)
		fmt.Fprintf(os.Stderr, "min: %d %d  offset: %d->", min, off, entry.FileOffset)
	}
	fmt.Fprintf(os.Stderr, "]\n")
}

func popContiguous(fileOffset *uint64, heap *heap.Heap[*entries.LogfileEntry]) {
	for entry, min, ok := heap.Pop(); ok; entry, min, ok = heap.Pop() {
		if *fileOffset == entry.FileOffset {
			dhprintf("JQUEUE advance o:%d\n", *fileOffset);
			*fileOffset += entry.WriteCount
		} else {
			dhprintf("JQUEUE no advance o:%d, e:%d\n",
					*fileOffset, entry.FileOffset);
			dhprintf("%s\n", heap);
			heap.Insert(min, entry)
			break
		}
	}
}

const MaxHeapSz = 2048

// This inserts a copy for safety. It is probably not necesary (it is only used for isok)
//
//	but this is safer.
func advanceEntry(entry *entries.LogfileEntry, o *OFile) error {
	e := *entry
	if o.offset == e.FileOffset {
		o.offset += e.WriteCount
		return nil
	}
	off := unifyOffset(e.FileOffset, e.RatchetOffset)
	o.heap.Insert(int(off), &e)
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
	log.Printf("Ofiles:\n")
	for _, o := range ofiles {
		fmt.Fprintf(os.Stderr, "ofile %s\n", o)
	}
	return nil
}

func isIncluded(n, a, b uint64) bool {
	return a <= n && n < b
}

// TODO: should check inode?
func isInRange(entry *entries.LogfileEntry, region Region) bool {
	begin, end := region.begin, region.end
	inr := isIncluded(begin, entry.FileOffset, entry.FileOffset+entry.WriteCount)
	inr = inr || isIncluded(end, entry.FileOffset, entry.FileOffset+entry.WriteCount)
	inr = inr || begin <= entry.FileOffset && entry.FileOffset+entry.WriteCount <= end
	return inr && entry.Inode == region.Inode
}

const MaxNRatchet = 512

//inode == 0, check all files, else check only the inode
//begin == 0 && end == 0, check the whole file
//precondition:  begin <= end

type Region struct {
	Inode uint64
	begin uint64
	end   uint64
}

type Renames map[uint64]*Rename

type SealFsDesc struct {
	kf       *os.File      //This will be buffered and seeked
	lf       io.ReadCloser //This is read in order, buffered but not seeked
	dirPath  string
	typeLog  int
	Magic    uint64
	NEntries uint64
}

func (rs Renames) String() string {
	s := ""
	for _, r := range rs {
		s += fmt.Sprintf("rename inode %s\n", r)
	}
	return s
}

func (rs Renames) AddRename(inode uint64, newinode uint64) {
	r := NewRename(uint64(inode), uint64(newinode))
	rs[r.Inode] = r
}

func OpenDesc(betakeyfile string, logfile string, dir string, typeLog int) (desc *SealFsDesc, err error) {
	kf, err := os.Open(betakeyfile)
	if err != nil {
		return nil, fmt.Errorf("can't open beta keyfile %s: %s", betakeyfile, err)
	}
	lf, err := os.Open(logfile)
	if err != nil {
		kf.Close()
		return nil, fmt.Errorf("can't open logfile %s: %s", logfile, err)
	}
	fil, err := lf.Stat()
	if err != nil {
		return nil, errors.New("can't stat log file")
	}
	nentries := uint64((fil.Size() - headers.SizeofLogfileHeader) / entries.SizeofEntry)
	desc = NewSealFsDesc(kf, lf, dir, typeLog, nentries)
	kh := &headers.KeyFileHeader{}
	err = kh.FillHeader(kf)
	if err != nil {
		desc.Close()
		return nil, errors.New("can't read beta key header")
	}
	desc.Magic = kh.Magic
	logHeader := &headers.LogFileHeader{}
	err = logHeader.FillHeader(lf)
	if err != nil {
		desc.Close()
		return nil, errors.New("can't read lheader")
	}
	if logHeader.Magic != desc.Magic {
		return nil, errors.New("desc magic numbers don't match")
	}
	return desc, nil
}

func NewSealFsDesc(kf *os.File, lf io.ReadCloser, dirPath string, typeLog int, nentries uint64) *SealFsDesc {
	return &SealFsDesc{kf: kf, lf: lf, dirPath: dirPath, typeLog: typeLog, NEntries: nentries}
}

func (desc *SealFsDesc) CheckKeystream(alphakfile string) (burnt uint64, nratchet uint64, err error) {
	alphaf, err := os.Open(alphakfile)
	if err != nil {
		return 0, 0, fmt.Errorf("can't open %s\n", alphakfile)
	}
	defer alphaf.Close()
	kh := &headers.KeyFileHeader{}
	err = kh.FillHeader(alphaf)
	if err != nil {
		return 0, 0, fmt.Errorf("can't read kalphahdr: %s", err)
	}
	if kh.Magic != desc.Magic {
		return 0, 0, fmt.Errorf("magic numbers don't match desc != kbeta")
	}
	nkeys := uint64(0)
	if kh.Burnt != headers.SizeofKeyfileHeader {
		nkeys = (kh.Burnt - headers.SizeofKeyfileHeader) / entries.FprSize
	}
	if desc.NEntries < nkeys {
		return 0, 0, fmt.Errorf("more keys burnt than entries")
	}
	err = CheckKeyStreams(alphaf, desc.kf, kh.Burnt)
	if err != nil {
		return 0, 0, fmt.Errorf("checkkeystreams: %s", err)
	}
	nratchet = 1
	if nkeys != 0 {
		nratchet = desc.NEntries / nkeys
	}
	return kh.Burnt, nratchet, nil
}

func (desc *SealFsDesc) Close() {
	desc.lf.Close()
	desc.kf.Close()
}

func (desc *SealFsDesc) LogFile() io.ReadCloser {
	return desc.lf
}
func (desc *SealFsDesc) SetLogFile(lf io.ReadCloser) {
	desc.lf = lf
}

func badOff(entry *entries.LogfileEntry, keyoff uint64, ratchetoffset uint64) {
	log.Printf("koffset %d or roff %d not correct: ", entry.KeyFileOffset, entry.RatchetOffset)
	fmt.Fprintf(os.Stderr, "should be %d %d", keyoff, ratchetoffset)
	fmt.Fprintf(os.Stderr, "%s\n", entry)
}

func badEntry(entry *entries.LogfileEntry, nratchet uint64) {
	log.Printf("can't verify entry with nratchet %d: ", nratchet)
	fmt.Fprintf(os.Stderr, "%s\n", entry)
}

func (sf *SealFsDesc) Verify(region Region, renames Renames, nratchet uint64) error {
	var file *os.File
	var keyc entries.KeyCache
	keyc.Drop()
	gotnratchet := false
	nbad := uint64(0)
	c := uint64(0)
	ratchetoffset := uint64(0)

	ofiles := make(map[uint64]*OFile)
	if err := scanDirFiles(sf.dirPath, ofiles, renames); err != nil {
		return fmt.Errorf("scanDirFiles %s", err)
	}
	if region.Inode == 0 && sf.typeLog != entries.LogSilent {
		dumpOFiles(ofiles)
	}
	entryFile := entries.NewEntryFile(sf.lf)
	keyR := entries.NewBufReadSeeker(sf.kf)
	for {
		entry, err := entryFile.ReadEntry()
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
		if !gotnratchet {
			keysNRatchet := nratchet
			gotnratchet, nratchet = entry.NRatchetDetect(file, keyR)
			if !gotnratchet {
				return fmt.Errorf("can't find a correct nratchet")
			}
			if keysNRatchet != nratchet {
				return fmt.Errorf("NRatchetDetect got nratchet %d but entries/keys is %d: nentries: %d\n", nratchet, keysNRatchet, sf.NEntries)
			}
			if sf.typeLog != entries.LogSilent {
				log.Printf("NRatchetDetect got nratchet %d\n", nratchet)
			}
		}
		if entry.Inode != entries.FakeInode {
			if region.Inode != 0 {
				if region.end != 0 && !isInRange(entry, region) {
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
		isok := entry.IsOk(file, keyR, &keyc, nratchet)
		if !isok {
			if sf.typeLog == entries.LogNone || sf.typeLog == entries.LogSilent {
				return errors.New("bad entry")
			}
			badEntry(entry, nratchet)
			nbad++
		}
		if entry.Inode != entries.FakeInode {
			err = entry.DumpLog(file, isok, sf.typeLog)
			if err != nil {
				log.Printf("can't dump log entry %s", entry)
				return err
			}
			if region.Inode != 0 && o.offset >= region.end {
				break
			}
		}
		keyOff := headers.SizeofKeyfileHeader + (c/nratchet)*entries.FprSize
		isWrongOff := entry.KeyFileOffset != keyOff || entry.RatchetOffset != ratchetoffset
		if region.Inode == 0 && isWrongOff && !DebugJQueue {
			badOff(entry, keyOff, ratchetoffset)
			return fmt.Errorf("incorrect koffset or roff")
		}
		c++
		ratchetoffset = (ratchetoffset + 1) % nratchet
	}
	if region.Inode == 0 && c%nratchet != 0 && !DebugJQueue {
		return fmt.Errorf("number of entries is not a multiple of nratchet: %d %d\n", c, nratchet)
	}
	err := checkTailOFiles(ofiles)
	if err != nil {
		return fmt.Errorf("error, checkTailOFiles %s\n", err)
	}
	if c == 0 {
		return fmt.Errorf("error, no entries in the log\n")
	}
	if nbad != 0 {
		if sf.typeLog != entries.LogSilent {
			fmt.Printf("error: %d entries verified, some bad logs: %d correct,  %d incorrect\n", c, c-nbad, nbad)
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

func CheckKeyStreams(alphaF *os.File, betaF *os.File, burnt uint64) (err error) {
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
	if prevalpha == prevbeta && burnt != headers.SizeofKeyfileHeader {
		return errors.New("keystreams are not valid: last burnt chunk is equal")
	}
	if burnt == uint64(fia.Size()) {
		log.Printf("alpha keystream is completely burnt\n")
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

func InodeBegEnd(args []string) (region Region, err error) {
	var n int

	if len(args) != 3 {
		return region, errors.New("short inode descriptor")
	}
	n, err = strconv.Atoi(args[0])
	if err != nil {
		return region, err
	}
	region.Inode = uint64(n)
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
