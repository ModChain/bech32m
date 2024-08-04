package bech32m

// See: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

// polymodUpdate returns the updated chk value for a given value v
// (go should inline this function easily)
func polymodUpdate(chk uint32, v byte) uint32 {
	top := chk >> 25
	chk = (chk&0x1ffffff)<<5 ^ uint32(v)
	for i, g := range [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3} {
		if (top>>i)&1 == 1 {
			chk ^= g
		} else {
			chk ^= 0
		}
	}
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
