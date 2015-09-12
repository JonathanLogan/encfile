// Package encfile implements encrypted paged files
package encfile

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/xts"
)

// KeySize is the _raw_ keysize
const KeySize = 64

// BlockSize of XTS cipher
const BlockSize = 16

const saltSize = 32
const gcmVer = 16
const encKeySize = KeySize + gcmVer
const headerSize = saltSize + encKeySize
const fileMode = os.ModePerm & 0600
const sectorFooter = gcmVer

// RandomSource of the packet
var RandomSource = rand.Reader

var (
	// ScryptN scrypt n param
	ScryptN = 16384
	// ScryptR scrypt r param
	ScryptR = 8
	// ScryptP scrypt p param
	ScryptP = 1
)

// ErrSectorSize .
var ErrSectorSize = errors.New("Sectorsize is no multiple of blocksize")

// EncryptedFile implements seekable file encryption
type EncryptedFile struct {
	filename   string
	encFunc    *xts.Cipher
	sectorSize int
	fd         *os.File
	salt       []byte
	encKey     []byte
	realKey    []byte
	seekPos    int64
}

func (ef *EncryptedFile) genKeyG(passphrase []byte) ([]byte, error) {
	if len(passphrase) == KeySize {
		return passphrase, nil
	}
	keyG, err := scrypt.Key(passphrase, ef.salt[:saltSize], ScryptN, ScryptR, ScryptP, KeySize)
	if err != nil {
		return nil, err
	}
	return keyG, nil
}

// ChangePass change passphrase of filename from old to new
func ChangePass(filename string, oldPassphrase, newPassphrase []byte) error {
	ef, err := Open(filename, oldPassphrase, BlockSize)
	if err != nil {
		return err
	}
	defer ef.Close()
	keyG, err := ef.genKeyG(newPassphrase)
	if err != nil {
		return err
	}
	ef.encKey = encryptSector(keyG, ef.salt, ef.realKey)
	if _, err := ef.fd.Write(ef.salt); err != nil {
		return err
	}
	if _, err := ef.fd.Write(ef.encKey); err != nil {
		return err
	}
	ef.fd.Sync()
	ef.fd.Close()
	return nil
}

// New returns a handle on an encrypted file
func New(filename string, passphrase []byte, sectorSize int) (*EncryptedFile, error) {
	var err error
	if sectorSize%BlockSize != 0 {
		return nil, ErrSectorSize
	}
	ef := new(EncryptedFile)
	ef.seekPos = -1
	ef.filename = filename
	ef.sectorSize = sectorSize
	ef.salt, ef.encKey = ef.readHeader()
	keyG, err := ef.genKeyG(passphrase)
	if err != nil {
		return nil, err
	}
	if ef.encKey == nil {
		ef.realKey = make([]byte, KeySize)
		_, err := io.ReadFull(RandomSource, ef.realKey)
		if err != nil {
			panic(err)
		}
		ef.encKey = encryptSector(keyG, ef.salt, ef.realKey)
	} else {
		ef.realKey, err = decryptSector(keyG, ef.salt, ef.encKey)
		if err != nil {
			return nil, err
		}
	}
	ef.encFunc, err = xts.NewCipher(aes.NewCipher, ef.realKey[:32])
	if err != nil {
		return nil, err
	}
	return ef, nil
}

func open(filename string, passphrase []byte, sectorSize int, openFlags int, doesExist bool) (*EncryptedFile, error) {
	var err error
	ef, err := New(filename, passphrase, sectorSize)
	if err != nil {
		return nil, err
	}
	existTest := ef.fileExists()
	if doesExist {
		if !existTest {
			return nil, os.ErrNotExist
		}
	} else {
		if existTest {
			return nil, os.ErrExist
		}
	}
	ef.fd, err = os.OpenFile(ef.filename, openFlags, fileMode)
	if err != nil {
		return nil, err
	}
	if !doesExist {
		ef.fd.Write(ef.salt)
		ef.fd.Write(ef.encKey)
		ef.fd.Sync()
	}
	return ef, nil
}

// Open a file for read and write, MUST exist
func Open(filename string, passphrase []byte, sectorSize int) (*EncryptedFile, error) {
	return open(filename, passphrase, sectorSize, os.O_RDWR, true)
}

// Create a file. May not exist
func Create(filename string, passphrase []byte, sectorSize int) (*EncryptedFile, error) {
	return open(filename, passphrase, sectorSize, os.O_RDWR|os.O_CREATE|os.O_EXCL, false)
}

// Append a file. Must exist
func Append(filename string, passphrase []byte, sectorSize int) (*EncryptedFile, error) {
	return open(filename, passphrase, sectorSize, os.O_WRONLY|os.O_APPEND, true)
}

// View a file. Open for reading only. Must exist
func View(filename string, passphrase []byte, sectorSize int) (*EncryptedFile, error) {
	return open(filename, passphrase, sectorSize, os.O_RDONLY, true)
}

// Stat of file
func (ef *EncryptedFile) Stat() (os.FileInfo, error) {
	if ef == nil {
		return nil, os.ErrInvalid
	}
	return ef.fd.Stat()
}

// Sync the file
func (ef *EncryptedFile) Sync() error {
	if ef == nil {
		return os.ErrInvalid
	}
	return ef.fd.Sync()
}

// Close the file
func (ef *EncryptedFile) Close() error {
	if ef == nil {
		return os.ErrInvalid
	}
	return ef.fd.Close()
}

func (ef *EncryptedFile) readHeader() (salt []byte, encKey []byte) {
	header := make([]byte, headerSize)
	if ef.fileExists() {
		f, err := os.Open(ef.filename)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = f.Read(header)
		if err != nil {
			panic(err)
		}
		return header[:saltSize], header[saltSize : saltSize+encKeySize]
	}
	_, err := io.ReadFull(RandomSource, header)
	if err != nil {
		panic(err)
	}
	return header[:saltSize], nil
}

func (ef *EncryptedFile) fileExists() bool {
	return FileExists(ef.filename)
}

// FileExists returns true if the file exists, false if not
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}
	return false
}

// ReadSector sector
func (ef *EncryptedFile) ReadSector(sector uint64) ([]byte, error) {
	ef.seekPos = -1
	if err := ef.seekSector(sector); err != nil {
		return nil, err
	}
	secData := make([]byte, ef.sectorSize+sectorFooter)
	n, err := ef.fd.Read(secData)
	if err != nil {
		return nil, err
	}
	if n < ef.sectorSize+sectorFooter {
		return nil, os.ErrNotExist
	}
	return decryptSector(ef.realKey[32:], ef.salt, secData)
}

// PadSector cuts or pads data to fit sector
func (ef *EncryptedFile) PadSector(data []byte) []byte {
	l := len(data)
	if l == ef.sectorSize {
		return data
	}
	if l > ef.sectorSize {
		return data[:ef.sectorSize]
	}
	ndata := make([]byte, ef.sectorSize)
	copy(ndata, data)
	return ndata
}

// WriteSector sector with data
func (ef *EncryptedFile) WriteSector(sector uint64, data []byte) error {
	ef.seekPos = -1
	if len(data) != ef.sectorSize {
		return os.ErrInvalid
	}
	if err := ef.seekSector(sector); err != nil {
		return err
	}
	secData := encryptSector(ef.realKey[32:], ef.salt, data)
	n, err := ef.fd.Write(secData)
	if err != nil {
		return err
	}
	if n < ef.sectorSize+sectorFooter {
		return os.ErrNotExist
	}
	return nil
}

// WriteSectorSync sector with data synched
func (ef *EncryptedFile) WriteSectorSync(sector uint64, data []byte) error {
	if err := ef.WriteSector(sector, data); err != nil {
		return err
	}
	if err := ef.Sync(); err != nil {
		return err
	}
	return nil
}

// WriteSectorPad writes partial data to the sector, zeroing out any additonal data in the sector
func (ef *EncryptedFile) WriteSectorPad(sector uint64, data []byte) error {
	data = ef.PadSector(data)
	return ef.WriteSector(sector, data)
}

func (ef *EncryptedFile) seekSector(sector uint64) error {
	seekPos := ef.calcSeek(sector)
	ret, err := ef.fd.Seek(seekPos, os.SEEK_SET)
	if err != nil {
		return err
	}
	if ret != seekPos {
		return os.ErrNotExist
	}
	return nil
}

// calcSeek calculate seek position from sector number
func (ef *EncryptedFile) calcSeek(sector uint64) int64 {
	return int64(headerSize + (sector * uint64(ef.sectorSize+sectorFooter)))
}

// CountSector returns the number of sectors in the file
func (ef *EncryptedFile) CountSector() uint64 {
	fi, err := ef.Stat()
	if err != nil {
		return 0
	}
	c := (fi.Size() - headerSize) / int64(ef.sectorSize+sectorFooter)
	if c <= 0 {
		return 0
	}
	return uint64(c)
}

// ZeroSector overwrites the sector with random data. Reading it will fail!
func (ef *EncryptedFile) ZeroSector(sector uint64) error {
	r := make([]byte, ef.sectorSize+sectorFooter)
	_, err := io.ReadFull(RandomSource, r)
	if err != nil {
		panic(err)
	}
	if err := ef.seekSector(sector); err != nil {
		return err
	}
	_, err = ef.fd.Write(r)
	return err
}

// Delete file by overwriting
func (ef *EncryptedFile) Delete() error {
	sector := uint64(0)
	totalSectors := ef.CountSector()
	for {
		err := ef.ZeroSector(sector)
		if err != nil && sector != totalSectors {
			return err
		}
		if sector >= totalSectors {
			break
		}
		sector++
	}
	if sector < totalSectors {
		return os.ErrInvalid
	}
	ef.fd.Seek(0, os.SEEK_SET)
	rr := make([]byte, headerSize)
	io.ReadFull(RandomSource, rr)
	_, err := ef.fd.Write(rr)
	if err != nil {
		return err
	}
	ef.fd.Sync()
	ef.fd.Truncate(0)
	ef.fd.Sync()
	ef.fd.Close()
	return os.Remove(ef.filename)
}

// Seek to relative off
func (ef *EncryptedFile) Seek(off int64) int64 {
	ef.seekPos = off
	return off
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func byteCopy(dst, src []byte) int {
	n := min(len(dst), len(src))
	for i := 0; i < n; i++ {
		dst[i] = src[i]
	}
	return n
}

func (ef *EncryptedFile) calcSectorOffset(off int64) (sector uint64, skip int) {
	if off < 0 {
		panic("negative offset")
	}
	sector = uint64(off / int64(ef.sectorSize))
	skip = int(off % int64(ef.sectorSize))
	return
}

// readPartial reads into b from position p. it starts writing to b at bpos, and at sector at secpos
func (ef *EncryptedFile) readPartial(sector uint64, b []byte, bpos, secpos int) (int, error) {
	d, err := ef.ReadSector(sector)
	if err != nil {
		return 0, err
	}
	n := byteCopy(b[bpos:], d[secpos:])
	return n, nil
}

// writePartial writes to sector starting with secpos bytes from b starting with bpos
func (ef *EncryptedFile) writePartial(sector uint64, b []byte, secpos, bpos int) (int, error) {
	var d []byte
	//  Dont read if we write a full sector matching sector boundary
	if len(b)-bpos >= ef.sectorSize && secpos == 0 {
		if err := ef.WriteSector(sector, b[bpos:bpos+ef.sectorSize]); err != nil {
			return 0, err
		}
		return ef.sectorSize, nil
	}
	// Write not matching sector boundaries, need that data first
	d, err := ef.ReadSector(sector)
	if err != nil {
		if err != io.EOF {
			return 0, err
		}
		d = make([]byte, ef.sectorSize)
	}
	n := byteCopy(d[secpos:], b[bpos:])
	if err := ef.WriteSector(sector, d); err != nil {
		return 0, err
	}
	return n, nil
}

// ReadAt position
func (ef *EncryptedFile) ReadAt(b []byte, off int64) (n int, err error) {
	l := len(b)
	sector, skip := ef.calcSectorOffset(off) // first sector
	n, err = ef.readPartial(sector, b, 0, skip)
	if err != nil {
		return n, err
	}
	// Read all sectors left that dont start partial
	for x := l - n; x > 0; x -= ef.sectorSize {
		sector++
		nt, err := ef.readPartial(sector, b, n, 0)
		n += nt
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// WriteAt b to off
func (ef *EncryptedFile) WriteAt(b []byte, off int64) (n int, err error) {
	l := len(b)
	sector, skip := ef.calcSectorOffset(off)     // first sector
	n, err = ef.writePartial(sector, b, skip, 0) // Write first part
	for x := l - n; x > 0; x -= ef.sectorSize {
		sector++
		nt, err := ef.writePartial(sector, b, 0, n)
		n += nt
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// Read form current position
func (ef *EncryptedFile) Read(b []byte) (n int, err error) {
	if ef.seekPos == -1 {
		return 0, os.ErrInvalid
	}
	n, err = ef.ReadAt(b, ef.seekPos)
	ef.seekPos += int64(n)
	return n, err
}

// Write b to file at current position
func (ef *EncryptedFile) Write(b []byte) (n int, err error) {
	if ef.seekPos == -1 {
		return 0, os.ErrInvalid
	}
	n, err = ef.WriteAt(b, ef.seekPos)
	ef.seekPos += int64(n)
	return n, err
}
