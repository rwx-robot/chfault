package crypto_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/chfault/chfault/crypto"
)

// TestRLP_KnownVectors 用 RLP 规范里的公开示例验证编码。
//
// 这些是 RFC/黄皮书中给出的例子，不是自造的。
func TestRLP_KnownVectors(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantHex string
	}{
		{"empty_string", []byte{}, "0x80"},
		{"single_byte_0x00", []byte{0x00}, "0x00"},
		{"single_byte_0x0f", []byte{0x0f}, "0x0f"},
		{"single_byte_0x7f", []byte{0x7f}, "0x7f"},
		{"string_dog", []byte("dog"), "0x83646f67"},
		{"string_cat_dog", []byte("catdog"), "0x86636174646f67"},
		// 56 字节 → 长形式
		{"string_56_bytes", bytes.Repeat([]byte("a"), 56),
			"0xb838" + hex.EncodeToString(bytes.Repeat([]byte("a"), 56))},
		// 55 字节 → 短形式（边界）
		{"string_55_bytes", bytes.Repeat([]byte("a"), 55),
			"0xb7" + hex.EncodeToString(bytes.Repeat([]byte("a"), 55))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := "0x" + hex.EncodeToString(crypto.EncodeBytes(tc.input))
			if got != tc.wantHex {
				t.Fatalf("编码不匹配\n want %s\n got  %s", tc.wantHex, got)
			}
		})
	}
}

// TestRLP_IntegerEncoding 验证整数的规范编码（最短表示）。
func TestRLP_IntegerEncoding(t *testing.T) {
	cases := []struct {
		v       uint64
		wantHex string
	}{
		{0, "0x80"},      // 0 编码为空串
		{1, "0x01"},      // 单字节小值直接编码
		{15, "0x0f"},     // 0x0f < 0x80
		{0x7f, "0x7f"},   // 边界
		{0x80, "0x8180"}, // 0x80 需要前缀
		{0xffff, "0x82ffff"},
		{1024, "0x820400"},
	}

	for _, tc := range cases {
		got := "0x" + hex.EncodeToString(crypto.EncodeUint64(tc.v))
		if got != tc.wantHex {
			t.Fatalf("整数 %d 编码不匹配\n want %s\n got  %s", tc.v, tc.wantHex, got)
		}
	}
}

// TestRLP_ListVectors 验证列表编码。
func TestRLP_ListVectors(t *testing.T) {
	// 空列表
	empty := crypto.EncodeList()
	if hex.EncodeToString(empty) != "c0" {
		t.Fatalf("空列表应为 0xc0，实际 %s", hex.EncodeToString(empty))
	}

	// ["cat", "dog"] → 0xc8 83636174 83646f67
	got := crypto.EncodeList(
		crypto.EncodeBytes([]byte("cat")),
		crypto.EncodeBytes([]byte("dog")),
	)
	const want = "c88363617483646f67"
	if hex.EncodeToString(got) != want {
		t.Fatalf("列表编码不匹配\n want %s\n got  %s", want, hex.EncodeToString(got))
	}

	// 嵌套列表 [ [], [[]], [ [], [[]] ] ] —— 黄皮书里的经典例子
	nested := crypto.EncodeList(
		crypto.EncodeList(),
		crypto.EncodeList(crypto.EncodeList()),
		crypto.EncodeList(
			crypto.EncodeList(),
			crypto.EncodeList(crypto.EncodeList()),
		),
	)
	const wantNested = "c7c0c1c0c3c0c1c0"
	if hex.EncodeToString(nested) != wantNested {
		t.Fatalf("嵌套列表编码不匹配\n want %s\n got  %s",
			wantNested, hex.EncodeToString(nested))
	}
}

// TestRLP_RoundTrip 验证编解码往返。
func TestRLP_RoundTrip(t *testing.T) {
	original := crypto.EncodeList(
		crypto.EncodeUint64(10086),                         // chainId
		crypto.EncodeUint64(0),                             // nonce
		crypto.EncodeUint64(21000),                         // gasLimit
		crypto.EncodeBytes(bytes.Repeat([]byte{0xaa}, 20)), // to
		crypto.EncodeBytes(nil),                            // value = 0
		crypto.EncodeBytes([]byte{0xde, 0xad}),             // data
	)

	item, err := crypto.DecodeStrict(original)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if !item.IsList {
		t.Fatal("应解码为列表")
	}
	if len(item.List) != 6 {
		t.Fatalf("应有 6 个元素，实际 %d", len(item.List))
	}

	chainID, err := item.List[0].Uint64()
	if err != nil || chainID != 10086 {
		t.Fatalf("chainId 解析错误: %v %d", err, chainID)
	}
	nonce, _ := item.List[1].Uint64()
	if nonce != 0 {
		t.Fatalf("nonce 应为 0，实际 %d", nonce)
	}
	if !bytes.Equal(item.List[5].Bytes, []byte{0xde, 0xad}) {
		t.Fatal("data 不匹配")
	}
}

// TestRLP_RejectsNonCanonical 验证拒绝非规范编码。
//
// 这是安全关键：如果同一个值有多种合法编码，同一笔交易就会有多个哈希，
// 攻击者可以利用它绕过去重与重放检查。
func TestRLP_RejectsNonCanonical(t *testing.T) {
	cases := []struct {
		name   string
		input  []byte
		reason string
	}{
		{
			name:   "integer_with_leading_zero",
			input:  []byte{0x82, 0x00, 0x05}, // 5 编码为 0x0005
			reason: "整数存在前导零",
		},
		{
			name:   "single_byte_as_long_string",
			input:  []byte{0x81, 0x05}, // 5 编码为 0x8105（应用单字节形式）
			reason: "单字节值使用了非规范的长编码",
		},
		{
			name:   "length_with_leading_zero",
			input:  []byte{0xb9, 0x00, 0x38}, // 长字符串但长度字段有前导零
			reason: "长度存在前导零",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item, _, err := crypto.Decode(tc.input)
			if err != nil {
				return // 在 Decode 层就拒绝了，正确
			}
			// 若 Decode 通过，Uint64 必须拒绝
			if _, err := item.Uint64(); err == nil {
				t.Fatalf("应拒绝非规范编码（%s），但通过了", tc.reason)
			}
		})
	}
}

// TestRLP_RejectsTrailingBytes 验证 DecodeStrict 拒绝多余字节。
func TestRLP_RejectsTrailingBytes(t *testing.T) {
	valid := crypto.EncodeUint64(1024)
	withTrailing := append(append([]byte{}, valid...), 0xff)

	if _, err := crypto.DecodeStrict(withTrailing); err == nil {
		t.Fatal("DecodeStrict 应拒绝 trailing bytes")
	}
}

// TestRLP_RejectsTruncated 验证拒绝被截断的输入。
func TestRLP_RejectsTruncated(t *testing.T) {
	// 声明 10 字节字符串但只给 3 字节
	truncated := []byte{0x8a, 0x01, 0x02, 0x03}
	if _, _, err := crypto.Decode(truncated); err == nil {
		t.Fatal("应拒绝被截断的输入")
	}
}

// TestRLP_BigIntEncoding 验证 big.Int 编码。
func TestRLP_BigIntEncoding(t *testing.T) {
	// 1 ETH = 10^18 wei
	oneETH := new(big.Int)
	oneETH.SetString("1000000000000000000", 10)

	enc := crypto.EncodeBigInt(oneETH)
	item, err := crypto.DecodeStrict(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	got, err := item.BigInt()
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Cmp(oneETH) != 0 {
		t.Fatalf("往返不一致\n want %s\n got  %s", oneETH, got)
	}

	// 0 应编码为 0x80
	if hex.EncodeToString(crypto.EncodeBigInt(big.NewInt(0))) != "80" {
		t.Fatal("big.Int(0) 应编码为 0x80")
	}
	// nil 同样
	if hex.EncodeToString(crypto.EncodeBigInt(nil)) != "80" {
		t.Fatal("nil big.Int 应编码为 0x80")
	}
}

// TestRLP_EncodeIsDeterministic 验证编码不依赖 map 或随机性。
func TestRLP_EncodeIsDeterministic(t *testing.T) {
	build := func() []byte {
		return crypto.EncodeList(
			crypto.EncodeUint64(1),
			crypto.EncodeBytes([]byte("hello")),
			crypto.EncodeUint64(42),
		)
	}
	first := build()
	for i := 0; i < 50; i++ {
		if !bytes.Equal(first, build()) {
			t.Fatal("RLP 编码不确定")
		}
	}
}
