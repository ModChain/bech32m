package bech32m

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Encode compute a Bech32 string given HRP and data values.
func Encode(hrp string, data []byte, spec int) string {
	if spec == CashAddr {
		combined := append(data, createCashChecksum(hrp[:len(hrp)-1], data)...)
		var ret bytes.Buffer
		ret.Grow(len(hrp) + len(combined))
		ret.WriteString(hrp)
		for _, p := range combined {
			ret.WriteByte(charset[p])
		}
		return ret.String()
	}

	combined := append(data, createChecksum(hrp, data, spec)...)

	var ret bytes.Buffer
	ret.Grow(len(hrp) + 1 + len(combined))
	ret.WriteString(hrp)
	ret.WriteString("1")
	for _, p := range combined {
		ret.WriteByte(charset[p])
	}
	return ret.String()
}

// Decode validate a Bech32/Bech32m string, and determine HRP and data.
func Decode(bechString string) (string, []byte, int, error) {
	if len(bechString) > 127 {
		return "", nil, Failed, ErrMaxLengthExceeded
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, Failed, ErrMixedCase
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndexByte(bechString, '1')
	cashAddr := false
	checksumLen := 6

	if pos < 0 {
		pos = strings.LastIndexByte(bechString, ':')
		if pos < 0 {
			return "", nil, Failed, fmt.Errorf("No separator character")
		}
		// CashAddr
		cashAddr = true
		checksumLen = 8
	} else if len(bechString) > 90 {
		return "", nil, Failed, ErrMaxLengthExceeded
	}
	if pos < 1 {
		return "", nil, Failed, fmt.Errorf("Empty HRP")
	}
	if pos+1+checksumLen > len(bechString) {
		return "", nil, Failed, fmt.Errorf("Too short checksum")
	}
	hrp := bechString[0:pos]
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, Failed, fmt.Errorf("HRP character out of range")
		}
	}
	data := []byte{}
	// for p := pos + 1; p < len(bechString); p++ {
	for p, c := range bechString[pos+1:] {
		d := deccharset[c&0x7f]
		if d == 0xff || c > 0x7f {
			if p+pos+checksumLen > len(bechString) {
				return "", nil, Failed, fmt.Errorf("Invalid character in checksum")
			}
			return "", nil, Failed, fmt.Errorf("Invalid data character %c", c)
		}
		data = append(data, d)
	}
	if cashAddr {
		// perform BCH Polymod (expect chk==0)
		chk := cashPolymodHrp(hrp, data)
		if chk != 1 {
			return "", nil, Failed, ErrInvalidChecksum
		}
		return hrp + ":", data[:len(data)-checksumLen], CashAddr, nil
	}
	spec := verifyChecksum(hrp, data)
	if spec == Failed {
		return "", nil, Failed, ErrInvalidChecksum
	}
	return hrp, data[:len(data)-checksumLen], spec, nil
}

var cashAddrLength = [...]int{20, 24, 28, 32, 40, 48, 56, 64} // in bytes

func CashAddrDecode(hrp, addr string) (byte, []byte, error) {
	hrpgot, data, spec, err := Decode(addr)
	if err != nil {
		return byte(0), nil, err
	}
	if spec != CashAddr {
		return byte(0), nil, fmt.Errorf("unexpected spec for address")
	}
	if hrp != "" && hrpgot != hrp {
		return byte(0xff), nil, fmt.Errorf("Invalid HRP")
	}
	if len(data) < 1 {
		return byte(0), nil, fmt.Errorf("Empty data section")
	}
	res := make([]byte, base32DecLen(len(data)))
	_, _, err = base32Decode(res, data)
	if err != nil {
		return byte(0), nil, err
	}
	vers := res[0]
	res = res[1:]

	if expectedLen := cashAddrLength[vers&7]; len(res) != expectedLen {
		return byte(0), nil, fmt.Errorf("payload length does not match expected length, got %d bytes instead of %d", len(res), expectedLen)
	}
	vers = vers >> 3

	return vers, res, nil
}

func CashAddrEncode(hrp string, vers byte, buf []byte) (string, error) {
	bit := (vers & 0xf) << 3
	found := false
	for n, l := range cashAddrLength {
		if len(buf) == l {
			bit |= byte(n)
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("cashaddr hash must be one of the specified bitlength")
	}

	data := make([]byte, base32EncLen(len(buf)+1))
	base32Encode(data, slices.Concat([]byte{bit}, buf))

	return Encode(hrp, data, CashAddr), nil
}

// SegwitAddrDecode decode a segwit address.
func SegwitAddrDecode(hrp, addr string) (byte, []byte, error) {
	hrpgot, data, spec, err := Decode(addr)
	if err != nil {
		return byte(0), nil, err
	}
	if hrpgot != hrp {
		return byte(0xff), nil, fmt.Errorf("Invalid HRP")
	}
	if len(data) < 1 {
		return byte(0), nil, fmt.Errorf("Empty data section")
	}
	if data[0] > 16 {
		return byte(0), nil, fmt.Errorf("Invalid witness version")
	}
	res := make([]byte, base32DecLen(len(data)-1))
	_, _, err = base32Decode(res, data[1:])
	if err != nil {
		return byte(0), nil, err
	}
	if len(res) < 2 || len(res) > 40 {
		return byte(0), nil, fmt.Errorf("Invalid program length (%d byte)", len(res))
	}
	if data[0] == 0 && len(res) != 20 && len(res) != 32 {
		return byte(0), nil, fmt.Errorf("Invalid program length for witness version 0 (per BIP141)")
	}
	if (data[0] == 0 && spec != Bech32) || (data[0] != 0 && spec != Bech32m) {
		return byte(0), nil, fmt.Errorf("Invalid checksum algorithm (bech32 instead of bech32m)")
	}
	return data[0], res, nil
}

// SegwitAddrEncode encode a segwit address.
func SegwitAddrEncode(hrp string, witver byte, witprog []byte) (string, error) {
	spec := Bech32m
	if witver == 0 {
		spec = Bech32
	}
	data := make([]byte, 1+base32EncLen(len(witprog)))
	base32Encode(data[1:], witprog)
	data[0] = witver
	ret := Encode(hrp, data, spec)
	_, _, err := SegwitAddrDecode(hrp, ret)
	if err != nil {
		return "", err
	}
	return ret, nil
}

// SegwitAddrEncodeNoCheck is the same as SegwitAddrEncode but it will not check if the generated address is valid
func SegwitAddrEncodeNoCheck(hrp string, witver byte, witprog []byte) (string, error) {
	spec := Bech32m
	if witver == 0 {
		spec = Bech32
	}
	data := make([]byte, 1+base32EncLen(len(witprog)))
	base32Encode(data[1:], witprog)
	data[0] = witver
	return Encode(hrp, data, spec), nil
}
