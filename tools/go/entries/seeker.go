package entries

import (
	"bufio"
	"io"
)

//BufReadSeeker is an io.ReadSeeker with some buffering

type BufReadSeeker struct {
	r      io.ReadSeeker
	br     *bufio.Reader
	offset int64
}

func (brs *BufReadSeeker) Read(p []byte) (n int, err error) {
	n, err = brs.br.Read(p)
	if err == nil {
		brs.offset += int64(n)
	}
	return n, err
}

func (brs *BufReadSeeker) Seek(offset int64, whence int) (noffset int64, err error) {
	if 0 == offset && whence == io.SeekCurrent {
		return brs.offset, nil
	}
	if brs.offset == offset && whence == io.SeekStart {
		return brs.offset, nil
	}
	noffset, err = brs.r.Seek(offset, whence)
	brs.br.Reset(brs.r)
	return noffset, err
}

func NewBufReadSeeker(r io.ReadSeeker) (brs *BufReadSeeker) {
	return &BufReadSeeker{r: r, br: bufio.NewReader(r)}
}
