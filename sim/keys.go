package sim

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 密钥与签名（与生产环境完全一致的签名路径）
//
// 私钥来源是确定性种子（32 字节重复 seed 字节），
// 签名/验签走 chfault/crypto 的 secp256k1 —— 与 keystore 的差异只在
// 密钥保管方式，不在密码学。
// ============================================================================

// TestKey 是仿真节点的密钥对。
type TestKey struct {
	Priv *secp256k1.PrivateKey
	Addr types.Address
}

// NewTestKey 从种子生成确定性密钥。
func NewTestKey(seed byte) *TestKey {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	priv := secp256k1.PrivKeyFromBytes(buf)
	addr, _ := crypto.PubKeyToAddress(priv.PubKey().SerializeUncompressed())
	return &TestKey{Priv: priv, Addr: addr}
}

// signerAdapter 实现 consensus.Signer。
type signerAdapter struct {
	key *TestKey
}

// Sign 实现 consensus.Signer。
func (s *signerAdapter) Sign(digest types.Hash) (types.Signature, error) {
	return crypto.Sign(digest, s.key.Priv)
}

// Verify 实现 consensus.Signer。
func (s *signerAdapter) Verify(digest types.Hash, sig types.Signature, addr types.Address) bool {
	return crypto.Verify(digest, sig, addr)
}
