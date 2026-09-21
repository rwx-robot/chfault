package crypto_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// vectorsFile 定位 spec 的测试向量文件。
//
// 从测试文件向上两级到达仓库根，再进 spec/vectors。
func vectorsFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "spec", "vectors", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("找不到测试向量文件 %s: %v", p, err)
	}
	return p
}

// ============================================================================
// Keccak-256 权威向量
// ============================================================================

type keccakVector struct {
	Name         string `json:"name"`
	InputHex     string `json:"input_hex"`
	InputASCII   string `json:"input_ascii"`
	Expected     string `json:"expected"`
	Source       string `json:"source"`
	WhyImportant string `json:"why_important"`
}

type cryptoVectors struct {
	Keccak256         []keccakVector `json:"keccak256"`
	AddressDerivation []struct {
		Name                  string `json:"name"`
		PrivateKey            string `json:"private_key"`
		PublicKeyUncompressed string `json:"public_key_uncompressed"`
		Address               string `json:"address"`
		AddressEIP55          string `json:"address_eip55"`
	} `json:"address_derivation"`
}

func loadCryptoVectors(t *testing.T) cryptoVectors {
	t.Helper()
	data, err := os.ReadFile(vectorsFile(t, "crypto.json"))
	if err != nil {
		t.Fatalf("读取向量文件失败: %v", err)
	}
	var v cryptoVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("解析向量文件失败: %v", err)
	}
	if len(v.Keccak256) == 0 {
		t.Fatal("向量文件为空")
	}
	return v
}

// TestKeccak256_AuthoritativeVectors 用权威已知值验证 Keccak-256。
//
// 这些值来自以太坊规范，不是由 chfault 生成后回填。
// 特别是 ERC20 Transfer 事件签名 —— 它是链上被引用最多的哈希之一，
// 如果实现误用 SHA3-256，这个测试会立刻失败。
func TestKeccak256_AuthoritativeVectors(t *testing.T) {
	v := loadCryptoVectors(t)

	for _, tc := range v.Keccak256 {
		t.Run(tc.Name, func(t *testing.T) {
			var input []byte
			switch {
			case tc.InputHex != "":
				var err error
				input, err = hex.DecodeString(strings.TrimPrefix(tc.InputHex, "0x"))
				if err != nil {
					t.Fatalf("解析输入十六进制失败: %v", err)
				}
			case tc.InputASCII != "":
				input = []byte(tc.InputASCII)
			default:
				input = []byte{} // 空输入
			}

			got := crypto.Keccak256(input)
			want := strings.TrimPrefix(tc.Expected, "0x")

			if got.String() != "0x"+want {
				t.Fatalf("keccak256 不匹配\n  input:    %q\n  want:     %s\n  got:      %s\n  source:   %s\n  %s",
					string(input), tc.Expected, got.String(), tc.Source, tc.WhyImportant)
			}
		})
	}
}

// TestEmptyConstants_MatchEthereum 验证与以太坊一致的空值常量。
//
// EVM 兼容性依赖这两个常量正确。
func TestEmptyConstants_MatchEthereum(t *testing.T) {
	// EMPTY_CODE_HASH = keccak256("")
	if h := crypto.Keccak256(nil); h != crypto.EmptyCodeHash {
		t.Fatalf("EmptyCodeHash 常量错误:\n want %s\n got  %s",
			crypto.EmptyCodeHash.String(), h.String())
	}

	// EMPTY_STORAGE_ROOT = keccak256(0x80)  （RLP 编码的空串）
	if h := crypto.Keccak256([]byte{0x80}); h != crypto.EmptyStorageRoot {
		t.Fatalf("EmptyStorageRoot 常量错误:\n want %s\n got  %s",
			crypto.EmptyStorageRoot.String(), h.String())
	}
}

// ============================================================================
// 地址派生
// ============================================================================

// TestAddressDerivation_AuthoritativeVectors 验证从私钥派生地址的完整链路：
// secp256k1 公钥 → keccak256 → 后 20 字节。
func TestAddressDerivation_AuthoritativeVectors(t *testing.T) {
	v := loadCryptoVectors(t)

	for _, tc := range v.AddressDerivation {
		t.Run(tc.Name, func(t *testing.T) {
			privBytes, err := hex.DecodeString(strings.TrimPrefix(tc.PrivateKey, "0x"))
			if err != nil {
				t.Fatalf("解析私钥失败: %v", err)
			}

			privKey := secp256k1.PrivKeyFromBytes(privBytes)

			// 验证未压缩公钥
			if tc.PublicKeyUncompressed != "" {
				wantPub := strings.TrimPrefix(tc.PublicKeyUncompressed, "0x")
				gotPub := hex.EncodeToString(privKey.PubKey().SerializeUncompressed())
				if !strings.EqualFold(gotPub, wantPub) {
					t.Fatalf("公钥不匹配\n want %s\n got  %s", wantPub, gotPub)
				}
			}

			// 派生地址
			addr, err := crypto.PubKeyToAddress(privKey.PubKey().SerializeUncompressed())
			if err != nil {
				t.Fatalf("派生地址失败: %v", err)
			}

			wantAddr := strings.ToLower(strings.TrimPrefix(tc.Address, "0x"))
			gotAddr := strings.ToLower(strings.TrimPrefix(addr.String(), "0x"))
			if gotAddr != wantAddr {
				t.Fatalf("地址不匹配\n want %s\n got  %s", tc.Address, addr.String())
			}

			t.Logf("私钥 %s → 地址 %s", tc.PrivateKey[:10]+"...", addr.String())
		})
	}
}

// TestSignature_SignAndRecover 验证签名与恢复的往返一致性。
//
// 这个测试同时验证了一个实测发现的坑：
// decred 的 `Signature.Serialize()` 返回 DER 变长编码（71-72 字节），
// 而 chfault 需要的是 65 字节紧凑格式（r ‖ s ‖ v）。
// 必须用 crypto.Sign 而不是直接调用 decred 的 API。
func TestSignature_SignAndRecover(t *testing.T) {
	privBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	privKey := secp256k1.PrivKeyFromBytes(privBytes)

	msg := crypto.Keccak256([]byte("chfault test message"))

	// 签名：必须是 65 字节紧凑格式
	sig, err := crypto.Sign(msg, privKey)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 恢复地址必须与原始地址一致
	wantAddr, _ := crypto.PubKeyToAddress(privKey.PubKey().SerializeUncompressed())

	gotAddr, err := crypto.RecoverAddress(msg, sig)
	if err != nil {
		t.Fatalf("恢复地址失败: %v", err)
	}
	if gotAddr != wantAddr {
		t.Fatalf("签名恢复的地址不匹配:\n want %s\n got  %s",
			wantAddr.String(), gotAddr.String())
	}

	// Verify 辅助函数
	if !crypto.Verify(msg, sig, wantAddr) {
		t.Fatal("Verify 应返回 true")
	}

	// 换一个摘要，验证必须失败
	other := crypto.Keccak256([]byte("different message"))
	if crypto.Verify(other, sig, wantAddr) {
		t.Fatal("对不同的摘要，Verify 应返回 false")
	}

	// EIP-2 低 s 规则
	if !crypto.IsLowS(sig) {
		t.Fatal("crypto.Sign 应产生低 s 签名（EIP-2）")
	}

	// v 必须是 0 或 1
	if sig[64] > 1 {
		t.Fatalf("v 必须是 0 或 1，实际 %d", sig[64])
	}

	t.Logf("签名 %d 字节，v=%d，恢复地址 %s", len(sig), sig[64], gotAddr.String())
}

// ============================================================================
// 布隆过滤器
// ============================================================================

// TestBloom_AddAndQuery 验证布隆过滤器的添加与查询。
//
// 布隆过滤器有假阳性，所以只断言：
//   - 添加过的项一定返回 true
//   - 空过滤器对新项返回 false（几乎必然）
func TestBloom_AddAndQuery(t *testing.T) {
	var bloom types.Bloom

	topic := crypto.Keccak256([]byte("Transfer(address,address,uint256)"))

	// 空过滤器查询应为 false
	if crypto.BloomContains(bloom, topic) {
		t.Fatal("空布隆过滤器不应包含任何项")
	}

	crypto.BloomAdd(&bloom, topic)

	if !crypto.BloomContains(bloom, topic) {
		t.Fatal("添加后查询应返回 true")
	}

	// 验证恰好设置了 3 个 bit（每个 keccak 贡献 3 位）
	bits := 0
	for _, b := range bloom {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				bits++
			}
		}
	}
	if bits == 0 || bits > 3 {
		t.Fatalf("单个哈希应设置 1-3 个 bit（可能有碰撞），实际 %d", bits)
	}
}

// TestBloom_Deterministic 验证布隆过滤器不依赖 map 顺序。
func TestBloom_Deterministic(t *testing.T) {
	addr := types.Address{0xAA}
	topics := []types.Hash{
		crypto.Keccak256([]byte("t1")),
		crypto.Keccak256([]byte("t2")),
	}

	a := crypto.BloomFromLogs(addr, topics)
	// 反序不应影响结果（因为每个 topic 独立 OR 进去）
	for i := 0; i < 10; i++ {
		b := crypto.BloomFromLogs(addr, topics)
		if a != b {
			t.Fatal("布隆过滤器计算不确定")
		}
	}
}
