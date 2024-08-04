package bech32m

import (
	"bytes"
	"fmt"
	"strings"
)

// Encode compute a Bech32 string given HRP and data values.
func Encode(hrp string, data []byte, spec int) string {
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
	if len(bechString) > 90 {
		return "", nil, Failed, ErrMaxLengthExceeded
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, Failed, ErrMixedCase
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndexByte(bechString, '1')
	if pos < 0 {
		return "", nil, Failed, fmt.Errorf("No separator character")
	}
	if pos < 1 {
		return "", nil, Failed, fmt.Errorf("Empty HRP")
	}
	if pos+7 > len(bechString) {
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
			if p+pos+6 > len(bechString) {
				return "", nil, Failed, fmt.Errorf("Invalid character in checksum")
			}
			return "", nil, Failed, fmt.Errorf("Invalid data character")
		}
		data = append(data, d)
	}
	spec := verifyChecksum(hrp, data)
	if spec == Failed {
		return "", nil, Failed, ErrInvalidChecksum
	}
	return hrp, data[:len(data)-6], spec, nil
}

func convertbits(data []byte, frombits, tobits uint, pad bool) ([]byte, error) {
	// General power-of-2 base conversion.
	acc := 0
	bits := uint(0)
	var ret []byte
	maxv := (1 << tobits) - 1
	maxAcc := (1 << (frombits + tobits - 1)) - 1
	for _, value := range data {
		acc = ((acc << frombits) | int(value)) & maxAcc
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("More than 4 padding bits")
	} else if ((acc << (tobits - bits)) & maxv) != 0 {
		return nil, fmt.Errorf("Non-zero padding in %d-to-%d conversion", tobits, frombits)
	}
	return ret, nil
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
	res, err := convertbits(data[1:], 5, 8, false)
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
