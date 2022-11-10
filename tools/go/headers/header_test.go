package headers_test

import (
	"sealfs/sealfs/headers"
	"testing"
)

func TestMarshalKeyHeader(t *testing.T) {
	kh := &headers.KeyFileHeader{0x123 ^ ^uint64(0), 0x234234 ^ ^uint64(0)}
	b, err := kh.MarshalBinary()
	if err != nil {
		t.Errorf("marshal key header %s", err)
	}
	kh2 := &headers.KeyFileHeader{}
	err = kh2.UnMarshalBinary(b)
	if err != nil {
		t.Errorf("unmarshal key header %s", err)
	}
	if kh2.Magic != kh.Magic || kh2.Burnt != kh.Burnt {
		t.Errorf("headers should be equal %v %v", kh, kh2)
	}
}

func TestMarshalLogHeader(t *testing.T) {
	lh := &headers.LogFileHeader{0x234234 ^ ^uint64(0)}
	b, err := lh.MarshalBinary()
	if err != nil {
		t.Errorf("marshal log header %s", err)
	}
	lh2 := &headers.LogFileHeader{}
	err = lh2.UnMarshalBinary(b)
	if err != nil {
		t.Errorf("unmarshal log header %s", err)
	}
	if lh2.Magic != lh.Magic {
		t.Errorf("headers should be equal %v %v", lh, lh2)
	}
}
