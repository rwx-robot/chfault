package crypto

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/chfault/chfault/types"
)

// 本文件实现 spec/00 §2.6 定义的签名格式：65 字节 = r(32) ‖ s(32) ‖ v(1)。
//
// ⚠️ 实现注意：decred 的 `Signature.Serialize()` 返回的是 **DER 变长编码**
// （71-72 字节），不是以太坊使用的紧凑格式。必须显式转换。
// 这是 M0 阶段实测发现的坑，记录在此避免后续重踩。

// secp256k1N 是曲线阶。
var secp256k1N = secp256k1.S256().N

// secp256k1HalfN 是 N/2，用于 EIP-2 的 s 规范化检查。
var secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)

// ============================================================================
// 签名
// ============================================================================

// Sign 对 32 字节摘要签名，返回 65 字节紧凑签名（r ‖ s ‖ v）。
//
// v 的语义（EIP-155 之后）：0 或 1（y_parity）。
// 注意：这**不是** legacy 交易的 27/28，也不是 chainId*2+35/36 ——
// 那两个是 legacy 交易在 RLP 层对 v 的包装方式，由 chain 包处理。
func Sign(digest types.Hash, privKey *secp256k1.PrivateKey) (types.Signature, error) {
	var out types.Signature

	// SignCompact 返回 65 字节：[recovery_id + 27 (+4 if compressed), r(32), s(32)]
	compact := ecdsa.SignCompact(privKey, digest.Bytes(), false)
	if len(compact) != 65 {
		return out, fmt.Errorf("crypto: SignCompact 返回 %d 字节，期望 65", len(compact))
	}

	// 重排为 r ‖ s ‖ v
	copy(out[0:32], compact[1:33])  // r
	copy(out[32:64], compact[33:65]) // s

	// 从头部字节提取 recovery id
	recID := compact[0]
	if recID >= 27 {
		recID -= 27
	}
	if recID >= 4 {
		return out, errors.New("crypto: 非法的 recovery id")
	}
	out[64] = recID // v = y_parity

	// EIP-2：s 必须 <= N/2，否则签名可塑性（第三方可翻转 s 得到另一个有效签名）
	s := new(big.Int).SetBytes(out[32:64])
	if s.Cmp(secp256k1HalfN) > 0 {
		return out, errors.New("crypto: 签名 s 值超过 N/2（不符合 EIP-2 低 s 规则）")
	}

	return out, nil
}

// ============================================================================
// 恢复
// ============================================================================

// RecoverPubKey 从签名与摘要恢复未压缩公钥（65 字节，0x04 前缀）。
func RecoverPubKey(digest types.Hash, sig types.Signature) ([]byte, error) {
	v := sig[64]
	if v > 1 {
		return nil, fmt.Errorf("crypto: v 必须是 0 或 1，实际 %d", v)
	}

	// 重排为 decred 的 compact 格式
	compact := make([]byte, 65)
	compact[0] = v + 27 // 未压缩
	copy(compact[1:33], sig[0:32])
	copy(compact[33:65], sig[32:64])

	pub, _, err := ecdsa.RecoverCompact(compact, digest.Bytes())
	if err != nil {
		return nil, fmt.Errorf("crypto: 恢复公钥失败: %w", err)
	}
	return pub.SerializeUncompressed(), nil
}

// RecoverAddress 从签名与摘要恢复发送者地址。
//
// 这是交易验证的第一步：任何人只要拿到交易内容 + 签名，
// 就能算出是谁签的，无需额外提供发送者字段。
func RecoverAddress(digest types.Hash, sig types.Signature) (types.Address, error) {
	pub, err := RecoverPubKey(digest, sig)
	if err != nil {
		return types.Address{}, err
	}
	return PubKeyToAddress(pub)
}

// Verify 验证签名是否来自指定地址。
func Verify(digest types.Hash, sig types.Signature, expected types.Address) bool {
	got, err := RecoverAddress(digest, sig)
	if err != nil {
		return false
	}
	return got == expected
}

// ============================================================================
// 工具
// ============================================================================

// IsLowS 检查签名是否满足 EIP-2 的低 s 规则。
//
// 高 s 的签名是可塑的：攻击者可以在不改变语义的情况下翻转签名，
// 导致同一个 (交易, 签名者) 有多个不同的有效交易哈希。
func IsLowS(sig types.Signature) bool {
	s := new(big.Int).SetBytes(sig[32:64])
	return s.Cmp(secp256k1HalfN) <= 0
}

// ZeroSignature 返回全零签名（用于占位与比较）。
func ZeroSignature() types.Signature { return types.Signature{} }

// SignatureFromBytes 从 65 字节构造签名。
func SignatureFromBytes(b []byte) (types.Signature, error) {
	var sig types.Signature
	if len(b) != types.SignatureLen {
		return sig, fmt.Errorf("crypto: 签名需要 %d 字节，实际 %d",
			types.SignatureLen, len(b))
	}
	copy(sig[:], b)
	return sig, nil
}
