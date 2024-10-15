package bech32m_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ModChain/bech32m"
)

func segwitScriptpubkey(witver byte, witprog []byte) []byte {
	// Construct a Segwit scriptPubKey for a given witness program.
	if witver != 0 {
		witver += 0x50
	}
	return append(append([]byte{witver}, byte(len(witprog))), witprog...)
}

var validBech32 = []string{
	"A12UEL5L",
	"a12uel5l",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	"?1ezyfcl",
}

var validBech32m = []string{
	"A1LQFN3A",
	"a1lqfn3a",
	"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
	"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
	"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
	"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
	"?1v759aa",
}

type cashAddrTestV struct {
	payloadSize int
	typ         byte
	addr        string
	hex         string
}

var validCashAddr = []cashAddrTestV{
	cashAddrTestV{20, 0, "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
	cashAddrTestV{20, 1, "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
	cashAddrTestV{20, 1, "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
	cashAddrTestV{20, 15, "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
	cashAddrTestV{24, 0, "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
	cashAddrTestV{24, 1, "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
	cashAddrTestV{24, 1, "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
	cashAddrTestV{24, 15, "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
	cashAddrTestV{28, 0, "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz", "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
	cashAddrTestV{28, 1, "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt", "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
	cashAddrTestV{28, 1, "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn", "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
	cashAddrTestV{28, 15, "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g", "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
	cashAddrTestV{32, 0, "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake", "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
	cashAddrTestV{32, 1, "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6", "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
	cashAddrTestV{32, 1, "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9", "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
	cashAddrTestV{32, 15, "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w", "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
	cashAddrTestV{40, 0, "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz", "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
	cashAddrTestV{40, 1, "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej", "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
	cashAddrTestV{40, 1, "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3", "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
	cashAddrTestV{40, 15, "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy", "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
	cashAddrTestV{48, 0, "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl", "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
	cashAddrTestV{48, 1, "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x", "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
	cashAddrTestV{48, 1, "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg", "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
	cashAddrTestV{48, 15, "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn", "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
	cashAddrTestV{56, 0, "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
	cashAddrTestV{56, 1, "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
	cashAddrTestV{56, 1, "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
	cashAddrTestV{56, 15, "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
	cashAddrTestV{64, 0, "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w", "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
	cashAddrTestV{64, 1, "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez", "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
	cashAddrTestV{64, 1, "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8", "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
	cashAddrTestV{64, 15, "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845", "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
}

var invalidBech32 = []string{
	" 1nwldj5",         // HRP character out of range
	"\x7F" + "1axkwrx", // HRP character out of range
	"\x80" + "1eym55h", // HRP character out of range
	// overall max length exceeded
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
	"pzry9x0s0muk",      // No separator character
	"1pzry9x0s0muk",     // Empty HRP
	"x1b4n0q5v",         // Invalid data character
	"li1dgmt3",          // Too short checksum
	"de1lg7wt" + "\xFF", // Invalid character in checksum
	"A1G7SGD8",          // checksum calculated with uppercase form of HRP
	"10a06t8",           // empty HRP
	"1qzzfhee",          // empty HRP
}

var invalidBech32m = []string{
	" 1xj0phk",         // HRP character out of range
	"\x7F" + "1g6xzxy", // HRP character out of range
	"\x80" + "1vctc34", // HRP character out of range
	// overall max length exceeded
	"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
	"qyrz8wqd2c9m",  // No separator character
	"1qyrz8wqd2c9m", // Empty HRP
	"y1b0jsk6g",     // Invalid data character
	"lt1igcx5c0",    // Invalid data character
	"in1muywd",      // Too short checksum
	"mm1crxm3i",     // Invalid character in checksum
	"au1s5cgom",     // Invalid character in checksum
	"M1VUXWEZ",      // Checksum calculated with uppercase form of HRP
	"16plkw9",       // Empty HRP
	"1p2gdwpf",      // Empty HRP
}

var validAddress = [][]string{
	{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
	{"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
	{"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
		"5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
	{"BC1SW50QGDZ25J", "6002751e"},
	{"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"},
	{"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		"0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
	{"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
		"5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
	{"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
		"512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
}

var invalidAddress = []string{
	// Invalid HRP
	"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
	// Invalid checksum algorithm (bech32m instead of bech32)
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
	// Invalid checksum algorithm (bech32m instead of bech32)
	"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
	// Invalid character in checksum
	"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
	// Invalid witness version
	"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
	// Invalid program length (1 byte)
	"bc1pw5dgrnzv",
	// Invalid program length (41 bytes)
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
	// Invalid program length for witness version 0 (per BIP141)
	"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
	// Mixed case
	"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
	// More than 4 padding bits
	//"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
	// Non-zero padding in 8-to-5 conversion
	//"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
	// Empty data section
	"bc1gmk9yu",
}

var invalidAddressEnc = [][]interface{}{
	{"BC", 0, 20},
	{"bc", 0, 21},
	{"bc", 17, 32},
	{"bc", 1, 1},
	{"bc", 16, 41},
}

func i2h(data []int) string {
	bs := []byte{}
	for _, i := range data {
		bs = append(bs, byte(i))
	}
	return hex.EncodeToString(bs)
}

func TestValidChecksum(t *testing.T) {
	// Test checksum creation and validation.
	specs := []int{bech32m.Bech32, bech32m.Bech32m}
	for _, spec := range specs {
		tests := validBech32m
		if spec == bech32m.Bech32 {
			tests = validBech32
		}
		for _, test := range tests {
			_, _, dspec, err := bech32m.Decode(test)
			if err != nil {
				t.Errorf("NG : %s / %+v", test, err)
				continue
			}
			if spec != dspec {
				t.Errorf("NG : %s", test)
				continue
			}
			pos := strings.LastIndex(test, "1")
			test2 := test[:pos+1] + string(test[pos+1]^1) + test[pos+2:]
			_, _, dspec, err = bech32m.Decode(test2)
			if err == nil {
				t.Errorf("NG : %s", test2)
				continue
			}
			t.Logf("OK : %s", test)
		}
	}
}

func TestValidCashAddr(t *testing.T) {
	for _, v := range validCashAddr {
		pos := strings.LastIndexByte(v.addr, ':')
		hrp := v.addr[:pos+1]
		vers, data, err := bech32m.CashAddrDecode(hrp, v.addr)
		if err != nil {
			t.Errorf("NG: %s %s", v.addr, err)
			continue
		}
		if len(data) != v.payloadSize {
			t.Errorf("Bad payload size %d != %d for addr %s", len(data), v.payloadSize, v.addr)
		}
		if vers != v.typ {
			t.Errorf("unexpected spec %d for addr %s", vers, v.addr)
		}
		if !bytes.Equal(data, must(hex.DecodeString(v.hex))) {
			t.Errorf("NG : unexpected result buffer for addr %s: %x != %s", v.addr, data, v.hex)
		}

		// test encoding
		addr, err := bech32m.CashAddrEncode(hrp, vers, data)
		if err != nil {
			t.Errorf("NG : failed to generate addr: %s", err)
		}
		if addr != v.addr {
			t.Errorf("NG : failed to get the original address when re-encoding cashaddr; %s != %s", v.addr, addr)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestInvalidChecksum(t *testing.T) {
	// Test checksum creation and validation.
	specs := []int{bech32m.Bech32, bech32m.Bech32m}
	for _, spec := range specs {
		tests := invalidBech32m
		if spec == bech32m.Bech32 {
			tests = invalidBech32
		}
		for _, test := range tests {
			_, _, dspec, err := bech32m.Decode(test)
			if err == nil {
				if spec == dspec {
					t.Errorf("NG : %s", test)
					continue
				}
			}
			t.Logf("OK : %s", err)
		}
	}
}

func TestValidAddress(t *testing.T) {
	// Test whether valid addresses decode to the correct output.
	for _, test := range validAddress {
		address := test[0]
		hexscript := test[1]
		hrp := "bc"
		witver, witprog, err := bech32m.SegwitAddrDecode(hrp, address)
		if err != nil {
			hrp = "tb"
			witver, witprog, err = bech32m.SegwitAddrDecode(hrp, address)
		}
		if err != nil {
			t.Errorf("NG : %s / %+v", test, err)
			continue
		}
		scriptpubkey := segwitScriptpubkey(witver, witprog)
		if hexscript != hex.EncodeToString(scriptpubkey) {
			t.Errorf("NG : %s", test)
			continue
		}
		addr, err := bech32m.SegwitAddrEncode(hrp, witver, witprog)
		if err != nil {
			t.Errorf("NG : %s / %+v", test, err)
			continue
		}
		if strings.ToLower(address) != addr {
			t.Errorf("NG : %s", test)
			continue
		}
		t.Logf("OK : %s", test)
	}
}

func TestInvalidAddress(t *testing.T) {
	// Test whether invalid addresses fail to decode.
	for _, test := range invalidAddress {
		ver, _, err := bech32m.SegwitAddrDecode("bc", test)
		if err == nil {
			t.Errorf("NG %d : %s", ver, test)
		} else {
			t.Logf("OK : %v", err)
		}
		_, _, err = bech32m.SegwitAddrDecode("tb", test)
		if err == nil {
			t.Errorf("NG : %s", test)
		} else {
			t.Logf("OK : %v", err)
		}
	}
}

func TestInvalidAddressEnc(t *testing.T) {
	// Test whether address encoding fails on invalid input.
	for _, test := range invalidAddressEnc {
		hrp := test[0].(string)
		version := test[1].(int)
		length := test[2].(int)
		prog := make([]byte, length, length)
		_, err := bech32m.SegwitAddrEncode(hrp, byte(version), prog)
		if err == nil {
			t.Logf("NG : %+v", test)
			t.Errorf("%+v", err)
			continue
		}
		t.Logf("OK : %v", err)
	}
}
