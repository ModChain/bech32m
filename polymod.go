package bech32m

// See: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

var polymodTable = [32]uint32{
	0x0, 0x3b6a57b2, 0x26508e6d, 0x1d3ad9df, 0x1ea119fa, 0x25cb4e48, 0x38f19797, 0x39bc025,
	0x3d4233dd, 0x628646f, 0x1b12bdb0, 0x2078ea02, 0x23e32a27, 0x18897d95, 0x5b3a44a, 0x3ed9f3f8,
	0x2a1462b3, 0x117e3501, 0xc44ecde, 0x372ebb6c, 0x34b57b49, 0xfdf2cfb, 0x12e5f524, 0x298fa296,
	0x1756516e, 0x2c3c06dc, 0x3106df03, 0xa6c88b1, 0x9f74894, 0x329d1f26, 0x2fa7c6f9, 0x14cd914b,
}

var cashPolymodTable = [32]uint64{
	0x0, 0x98f2bc8e61, 0x79b76d99e2, 0xe145d11783, 0xf33e5fb3c4, 0x6bcce33da5, 0x8a89322a26, 0x127b8ea447,
	0xae2eabe2a8, 0x36dc176cc9, 0xd799c67b4a, 0x4f6b7af52b, 0x5d10f4516c, 0xc5e248df0d, 0x24a799c88e, 0xbc552546ef,
	0x1e4f43e470, 0x86bdff6a11, 0x67f82e7d92, 0xff0a92f3f3, 0xed711c57b4, 0x7583a0d9d5, 0x94c671ce56, 0xc34cd4037,
	0xb061e806d8, 0x28935488b9, 0xc9d6859f3a, 0x512439115b, 0x435fb7b51c, 0xdbad0b3b7d, 0x3ae8da2cfe, 0xa21a66a29f,
}

// polymodUpdate returns the updated chk value for a given value v
// (go should inline this function easily)
func polymodUpdate(chk uint32, v byte) uint32 {
	top := (chk >> 25) & 0x1f
	chk = (chk&0x1ffffff)<<5 ^ uint32(v)
	chk ^= polymodTable[top]
	return chk
}

// polymodHrp is similar to polymod except it will follow hrp rules for the hrp part, and not
// perform any memory allocation during its process
func polymodHrp(hrp string, values ...[]byte) uint32 {
	chk := uint32(1)
	for _, c := range []byte(hrp) {
		chk = polymodUpdate(chk, c>>5)
	}
	chk = polymodUpdate(chk, 0)
	for _, c := range []byte(hrp) {
		chk = polymodUpdate(chk, c&31)
	}

	for _, value := range values {
		for _, v := range value {
			chk = polymodUpdate(chk, v)
		}
	}

	return chk
}

// cashPolymodUpdate returns the updated chk value for a given value v
func cashPolymodUpdate(chk uint64, v byte) uint64 {
	top := (chk >> 35) & 0x1f
	chk = (chk&0x07ffffffff)<<5 ^ uint64(v)
	chk ^= cashPolymodTable[top]
	return chk
}

// cashPolymodHrp is similar to polymod except it will follow hrp rules for the hrp part, and not
// perform any memory allocation during its process while applying rules specific to bitcoincash
//
// Details: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
func cashPolymodHrp(hrp string, values ...[]byte) uint64 {
	chk := uint64(1)
	for _, c := range []byte(hrp) {
		chk = cashPolymodUpdate(chk, c&31)
	}
	chk = cashPolymodUpdate(chk, 0)
	for _, value := range values {
		for _, v := range value {
			chk = cashPolymodUpdate(chk, v)
		}
	}

	return chk ^ 1
}
