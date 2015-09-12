package encfile

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"path"
	"strconv"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tdata := []byte("TestData")
	passphrase := []byte("A great little thing whatever")
	badpassphrase := []byte("A great little err whatever")
	tdir := path.Join(os.TempDir(), "encfile-tests")
	os.MkdirAll(tdir, 0700)
	filename := path.Join(tdir, strconv.Itoa(int(time.Now().Unix())))
	_, err := Open(filename, passphrase, 512)
	if err == nil {
		t.Error("Open must return error on opening non-existing file")
	}
	_, err = Append(filename, passphrase, 512)
	if err == nil {
		t.Error("Append must return error on opening non-existing file")
	}
	_, err = View(filename, passphrase, 512)
	if err == nil {
		t.Error("View must return error on opening non-existing file")
	}
	ef, err := Create(filename, passphrase, 512)
	if err != nil {
		t.Errorf("Create: %s", err)
	}
	if err = ef.Close(); err != nil {
		t.Errorf("Close: %s", err)
	}
	_, err = View(filename, badpassphrase, 512)
	if err == nil {
		t.Error("View must return error on opening with bad passphrase")
	}
	ef, err = View(filename, passphrase, 512)
	if err != nil {
		t.Errorf("View: %s", err)
	}

	if err = ef.Close(); err != nil {
		t.Errorf("Close: %s", err)
	}

	ef, err = Open(filename, passphrase, 512)
	if err != nil {
		t.Errorf("Open: %s", err)
	}
	err = ef.WriteSector(0, make([]byte, 10))
	if err == nil {
		t.Error("WriteSector must fail on short sector")
	}
	tdatar := ef.PadSector(tdata)
	err = ef.WriteSector(0, tdatar)
	if err != nil {
		t.Errorf("WriteSector: %s", err)
	}
	tdatar2, err := ef.ReadSector(0)
	if err != nil {
		t.Errorf("ReadSector: %s", err)
	}
	if !bytes.Equal(tdatar, tdatar2) {
		t.Error("Write/Read data no match")
	}
	tdatar = ef.PadSector([]byte("TestData second write"))
	err = ef.WriteSector(0, tdatar)
	if err != nil {
		t.Errorf("WriteSector: %s", err)
	}
	tdatar2, err = ef.ReadSector(0)
	if err != nil {
		t.Errorf("ReadSector: %s", err)
	}
	if !bytes.Equal(tdatar, tdatar2) {
		t.Error("Write/Read data no match")
	}
	tdatar1 := ef.PadSector([]byte("TestData write second sector"))
	err = ef.WriteSector(1, tdatar1)
	if err != nil {
		t.Errorf("WriteSector: %s", err)
	}
	tdatar2, err = ef.ReadSector(1)
	if err != nil {
		t.Errorf("ReadSector: %s", err)
	}
	if !bytes.Equal(tdatar1, tdatar2) {
		t.Error("Write/Read data no match")
	}
	tdatar2, err = ef.ReadSector(0)
	if err != nil {
		t.Errorf("ReadSector: %s", err)
	}
	if !bytes.Equal(tdatar, tdatar2) {
		t.Error("Write/Read data no match")
	}
	tdatar1 = ef.PadSector([]byte("Wide write"))
	err = ef.WriteSector(1000, tdatar1)
	if err != nil {
		t.Errorf("WriteSector: %s", err)
	}
	tdatar2, err = ef.ReadSector(1000)
	if err != nil {
		t.Errorf("ReadSector: %s", err)
	}
	if !bytes.Equal(tdatar1, tdatar2) {
		t.Error("Write/Read data no match")
	}
	b := make([]byte, 10)
	n, err := ef.readPartial(0, b, 2, 3)
	if err != nil {
		t.Errorf("readPartial %s", err)
	}
	_ = n
	b = make([]byte, ef.sectorSize*2)
	n, err = ef.ReadAt(b, 0)
	if err != nil {
		t.Errorf("ReadAt %s", err)
	}

	//----------
	err = ef.ZeroSector(1)
	if err != nil {
		t.Errorf("ZeroSector: %s", err)
	}
	_, err = ef.ReadSector(1)
	if err == nil {
		t.Errorf("ReadSector must fail on invalid sector")
	}
	err = ef.Delete()
	if err != nil {
		t.Errorf("Delete: %s", err)
	}
}

func randPos(maxlen, maxpos, lastpos int) (pos, length int64) {
	mrand.Seed(time.Now().UnixNano())
	maxlenI, maxposI, lastposI := int64(maxlen), int64(maxpos), int64(lastpos)
	for (pos+length > lastposI) || (pos+length == 0) {
		pos = mrand.Int63() % maxposI
		length = mrand.Int63() % maxlenI
	}
	return int64(pos), int64(length)
}

func TestRandomAccess(t *testing.T) {
	tdataSize := 20
	sectorSize := 512
	tdata := make([]byte, sectorSize*tdataSize)
	io.ReadFull(rand.Reader, tdata)
	passphrase := []byte("A great little thing whatever")
	tdir := path.Join(os.TempDir(), "encfile-tests")
	os.MkdirAll(tdir, 0700)
	filename := path.Join(tdir, strconv.Itoa(int(time.Now().Unix()))+".rad")
	ef, err := Create(filename, passphrase, sectorSize)
	if err != nil {
		t.Errorf("Create: %s", err)
	}
	n, err := ef.WriteAt(tdata, 0)
	if err != nil {
		t.Errorf("WriteAt: %s", err)
	}
	if n != len(tdata) {
		t.Errorf("Incomplete write: %d != %d", n, len(tdata))
	}

	for i := 0; i < 1000; i++ {
		pos, length := randPos(sectorSize*(tdataSize/2), sectorSize*(tdataSize-1), sectorSize*tdataSize-1)
		test := make([]byte, length)
		n, err = ef.ReadAt(test, pos)
		if err != nil {
			t.Fatalf("Read error: %s", err)
		}
		if int64(n) != length {
			t.Error("Incomplete read: %d %d", n, length)
		}
		if !bytes.Equal(test, tdata[pos:pos+length]) {
			t.Errorf("Read does not match image: %d %d", pos, length)
		}
		pos, length = randPos(sectorSize*(tdataSize/2), sectorSize*(tdataSize-1), sectorSize*tdataSize-1)
		test = make([]byte, length)
		io.ReadFull(rand.Reader, test)
		n, err = ef.WriteAt(test, pos)
		if err != nil {
			t.Fatalf("Write error: %s", err)
		}
		if int64(n) != length {
			t.Error("Incomplete write: %d %d", n, length)
		}
		copy(tdata[pos:pos+length], test)
	}
	for i := 0; i < 1000; i++ {
		pos, length := randPos(sectorSize*(tdataSize/2), sectorSize*(tdataSize-1), sectorSize*tdataSize-1)
		pos = int64(sectorSize)
		length = int64(sectorSize*2) + 10 // + mrand.Int63()%int64(sectorSize)
		td2 := make([]byte, length)
		io.ReadFull(rand.Reader, td2)
		td3 := make([]byte, length)
		n1, _ := ef.WriteAt(td2, pos)
		n2, _ := ef.ReadAt(td3, pos)
		if !bytes.Equal(td2, td3) {
			fmt.Print("Error:\n")
			fmt.Printf("\tPos: %d, %d, %d\n", pos, pos%int64(sectorSize), pos/int64(sectorSize))
			fmt.Printf("\tLength: %d, %d, %d\n", length, length%int64(sectorSize), length/int64(sectorSize))
			fmt.Printf("\tWL: %d  RL: %d\n", n1, n2)
			fmt.Printf("\t%x\n\t%x\n", td2[sectorSize-10:sectorSize+10], td3[sectorSize-10:sectorSize+10])
			// } else {
			// 	fmt.Print("OK:\n")
			// 	fmt.Printf("\tPos: %d, %d, %d\n", pos, pos%int64(sectorSize), pos/int64(sectorSize))
			// 	fmt.Printf("\tLength: %d, %d, %d\n", length, length%int64(sectorSize), length/int64(sectorSize))
			// 	fmt.Printf("\tWL: %d  RL: %d\n", n1, n2)
		}
	}
	if err = ef.Delete(); err != nil {
		t.Errorf("Close: %s", err)
	}
}

func TestGCM(t *testing.T) {
	msg := []byte("Secret message129389898123")
	key := [32]byte{0xff, 0x01, 0x02}
	nonce := [16]byte{0x01, 0x01, 0xaa}
	d := encryptSector(key[:], nonce[:], msg)
	msg2, err := decryptSector(key[:], nonce[:], d)
	if err != nil {
		t.Fatalf("Decrypt failed: %s", err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Errorf("Messages dont match: \n%s\n%s\n", string(msg), string(msg2))
	}
}
