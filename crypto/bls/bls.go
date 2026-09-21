// Package bls 实现 BLS12-381 聚合签名（ADR-014）。
//
// 采用以太坊标准的 **minimal-pubkey-size** 变体：
//   - 签名 σ ∈ G1（48 字节压缩）
//   - 公钥 pk ∈ G2（96 字节压缩）
//   - 消息 → 曲线：G1.HashToCurve（domain 分隔 "chfault-bls-v1"）
//
// 聚合能力（共识 QC 的核心收益）：
//   - n 个验证者的投票聚合成 1 个签名 + 1 个位图（QC 从 O(n) 降到 O(1) 传输）
//   - FastAggregateVerify：同消息多方签名，用公钥加法聚合验证（一次配对）
//
// 纯 Go 实现（kilic/bls12-381）—— 保持 CGO_ENABLED=0 的静态单二进制
// 与四平台交叉编译承诺（docs/blueprint/02 §2.6）。
//
// ⚠️ 生产加固清单（M3）：密钥零化、防侧信道（常数时间标量乘——kilic 已保证）、
// 消息去重（同一签名者不能对同一消息计两次）。
package bls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"

	"github.com/chfault/chfault/crypto"
)

// 常量。
const (
	// SecretKeyLen 私钥长度（32 字节标量）。
	SecretKeyLen = 32
	// PublicKeyLen 公钥长度（G2 压缩，以太坊标准）。
	PublicKeyLen = 96
	// SignatureLen 签名长度（G1 压缩）。
	SignatureLen = 48

	// domain 消息哈希的域分隔符（跨协议重放保护）。
	domain = "chfault-bls-v1"
)

// 错误。
var (
	// ErrInvalidSecretKey 私钥非法（零或超阶）。
	ErrInvalidSecretKey = errors.New("bls: 私钥非法")
	// ErrInvalidSignature 签名非法（点不在曲线上/子群外）。
	ErrInvalidSignature = errors.New("bls: 签名非法")
	// ErrInvalidPublicKey 公钥非法。
	ErrInvalidPublicKey = errors.New("bls: 公钥非法")
	// ErrEmptyAggregate 空聚合（至少一个签名）。
	ErrEmptyAggregate = errors.New("bls: 聚合列表为空")
)

// ============================================================================
// 引擎（包级单例 —— kilic 的 Engine 是无状态的静态表 + 方法集）
// ============================================================================

var engine = bls12381.NewEngine()

// ============================================================================
// 密钥
// ============================================================================

// SecretKey 是 BLS 私钥（Fr 标量）。
type SecretKey struct {
	fr bls12381.Fr
}

// KeyGen 从种子派生私钥（确定性 —— 与 secp256k1 的 dev 密钥同源规则）。
func KeyGen(seed []byte) (*SecretKey, error) {
	// keccak(seed) → big.Int mod r → Fr（避免 FromBytes 对超阶输入的要求）
	h := sha256.Sum256(seed)
	k := new(big.Int).SetBytes(h[:])
	r, _ := new(big.Int).SetString(
		"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	k.Mod(k, r)
	if k.Sign() == 0 {
		return nil, ErrInvalidSecretKey
	}
	sk := &SecretKey{}
	// big.Int → 32 字节 BE → Fr
	buf := make([]byte, 32)
	k.FillBytes(buf)
	sk.fr.FromBytes(buf)
	return sk, nil
}

// PublicKey 推导公钥（pk = g2 * sk，压缩 96 字节）。
func (sk *SecretKey) PublicKey() PublicKey {
	g2 := engine.G2
	pk := g2.One()
	g2.MulScalar(pk, g2.One(), &sk.fr)
	return PublicKey(g2.ToCompressed(pk))
}

// ============================================================================
// 公钥与签名（压缩字节表示 —— wire 友好）
// ============================================================================

// PublicKey 是压缩公钥（96 字节）。
type PublicKey []byte

// Signature 是压缩签名（48 字节）。
type Signature []byte

// parseSig 解压签名。
func parseSig(sig Signature) (*bls12381.PointG1, error) {
	if len(sig) != SignatureLen {
		return nil, fmt.Errorf("%w: 长度 %d ≠ %d", ErrInvalidSignature, len(sig), SignatureLen)
	}
	p, err := engine.G1.FromCompressed(sig)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	if !engine.G1.InCorrectSubgroup(p) {
		return nil, ErrInvalidSignature
	}
	return p, nil
}

// parsePK 解压公钥。
func parsePK(pk PublicKey) (*bls12381.PointG2, error) {
	if len(pk) != PublicKeyLen {
		return nil, fmt.Errorf("%w: 长度 %d ≠ %d", ErrInvalidPublicKey, len(pk), PublicKeyLen)
	}
	p, err := engine.G2.FromCompressed(pk)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	if !engine.G2.InCorrectSubgroup(p) {
		return nil, ErrInvalidPublicKey
	}
	return p, nil
}

// hashToG1 消息映射到曲线（domain 分隔）。
func hashToG1(msg []byte) *bls12381.PointG1 {
	p, _ := engine.G1.HashToCurve(msg, []byte(domain))
	return p
}

// ============================================================================
// 签名与验证
// ============================================================================

// Sign 签名：σ = H(msg) * sk。
func (sk *SecretKey) Sign(msg []byte) Signature {
	g1 := engine.G1
	sigma := g1.One()
	g1.MulScalar(sigma, hashToG1(msg), &sk.fr)
	return Signature(g1.ToCompressed(sigma))
}

// Verify 单签名验证：e(σ, g2gen) == e(H(msg), pk)。
func Verify(pk PublicKey, msg []byte, sig Signature) bool {
	pkPoint, err := parsePK(pk)
	if err != nil {
		return false
	}
	sigPoint, err := parseSig(sig)
	if err != nil {
		return false
	}

	// e(σ, g2gen) = e(H(msg), pk)
	// 用 AddPairInv 技巧一次配对检查：e(σ, g2gen) · e(-H(msg), pk) == 1
	negH := engine.G1.New()
	engine.G1.Neg(negH, hashToG1(msg))
	eng := bls12381.NewEngine()
	eng.AddPair(sigPoint, engine.G2.One())
	eng.AddPair(negH, pkPoint)
	return eng.Check()
}

// ============================================================================
// 聚合
// ============================================================================

// Aggregate 聚合多个签名（G1 群加法）。
func Aggregate(sigs []Signature) (Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrEmptyAggregate
	}
	g1 := engine.G1
	acc, err := parseSig(sigs[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(sigs); i++ {
		p, err := parseSig(sigs[i])
		if err != nil {
			return nil, err
		}
		g1.Add(acc, acc, p)
	}
	return Signature(g1.ToCompressed(acc)), nil
}

// AggregatePublicKeys 聚合公钥（G2 群加法）。
func AggregatePublicKeys(pks []PublicKey) (PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrEmptyAggregate
	}
	g2 := engine.G2
	acc, err := parsePK(pks[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(pks); i++ {
		p, err := parsePK(pks[i])
		if err != nil {
			return nil, err
		}
		g2.Add(acc, acc, p)
	}
	return PublicKey(g2.ToCompressed(acc)), nil
}

// FastAggregateVerify 快速聚合验证（**同一消息**、多方签名 —— QC 场景）：
//
//	e(σ_agg, g2gen) == e(H(msg), pk1 + pk2 + ... + pkn)
//
// 一次配对 + 一次 G2 加法 —— n 个验证者的验证成本 O(1) 配对。
func FastAggregateVerify(pks []PublicKey, msg []byte, sig Signature) bool {
	if len(pks) == 0 {
		return false
	}
	aggPK, err := AggregatePublicKeys(pks)
	if err != nil {
		return false
	}
	return Verify(aggPK, msg, sig)
}

// AggregateVerify 多消息聚合验证（不同消息 —— 较少用于 QC，备用 API）：
//
//	e(σ_agg, g2gen) == Π e(H(msg_i), pk_i)
func AggregateVerify(pks []PublicKey, msgs [][]byte, sig Signature) bool {
	if len(pks) == 0 || len(pks) != len(msgs) {
		return false
	}
	sigPoint, err := parseSig(sig)
	if err != nil {
		return false
	}

	eng := bls12381.NewEngine()
	// 右侧累积：Π e(H(m_i), pk_i) 用配对前 G1 侧乘积无法合并（不同消息），
	// 标准做法是逐对累乘 GT —— kilic 用 AddPair 累加后一次 Check。
	// 但 Σ e(H_i, pk_i) ≠ e(ΣH_i, Σpk_i)（消息不同）——
	// 这里用 AddPairInv 技巧：e(σ_agg, g2gen) · Π e(-H(m_i), pk_i) == 1
	eng.AddPair(sigPoint, engine.G2.One())
	for i := range pks {
		pkPoint, err := parsePK(pks[i])
		if err != nil {
			return false
		}
		negH := engine.G1.New()
		engine.G1.Neg(negH, hashToG1(msgs[i]))
		eng.AddPair(negH, pkPoint)
	}
	return eng.Check()
}

// ============================================================================
// 消息摘要约定（与 consensus 层对齐）
// ============================================================================

// SignMessage 组合 domain 与消息（consensus 层传 digest 时直接用 digest）。
func SignMessage(sk *SecretKey, msg []byte) Signature {
	return sk.Sign(msg)
}

// 编译期引用检查
var _ = crypto.Keccak256

// ============================================================================
// 与共识验证者身份的对齐（ADR-014 落地的接线约定）
// ============================================================================

// KeyFromSeed 从 20 字节地址派生 BLS 密钥（确定性，验证者身份一致）：
// 同一验证者的 secp256k1 地址与其 BLS 公钥稳定绑定（dev 模式）。
// M3 keystore 化后：secp256k1 与 BLS 密钥分开保管，但派生规则不变。
func KeyFromSeed(addrSeed []byte) (*SecretKey, error) {
	return KeyGen(append([]byte("chfault-bls:"), addrSeed...))
}
