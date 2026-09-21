package consensus_test

import (
	"testing"

	"github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/crypto"
	cbls "github.com/chfault/chfault/crypto/bls"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// verifyQCBLS 的单元测试 —— 位图 + BLS 聚合验证路径
// ============================================================================

// blsSignerAdapter 把 crypto/bls 适配为 consensus.BLSSigner。
type blsSignerAdapter struct {
	keys map[types.Address]*cbls.SecretKey
}

func (a *blsSignerAdapter) SignBLS(msg []byte) ([]byte, error) {
	// 单节点适配器没有"自己"的概念 —— QC 测试直接用 per-addr 聚合
	return nil, errNotSupported
}

var errNotSupported = &testErr{"not supported in test adapter"}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

func (a *blsSignerAdapter) BLSPublicKey() []byte { return nil }

func (a *blsSignerAdapter) BLSPublicKeyOf(addr types.Address) ([]byte, bool) {
	if k, ok := a.keys[addr]; ok {
		return k.PublicKey(), true
	}
	return nil, false
}

func (a *blsSignerAdapter) BLSPubKeysByAddrs(addrs []types.Address) ([][]byte, bool) {
	out := make([][]byte, 0, len(addrs))
	for _, addr := range addrs {
		k, ok := a.keys[addr]
		if !ok {
			return nil, false
		}
		out = append(out, k.PublicKey())
	}
	return out, true
}

func (a *blsSignerAdapter) BLSFastVerify(pks [][]byte, msg []byte, sig []byte) bool {
	typed := make([]cbls.PublicKey, 0, len(pks))
	for _, pk := range pks {
		typed = append(typed, cbls.PublicKey(pk))
	}
	return cbls.FastAggregateVerify(typed, msg, sig)
}

// devSigner 实现 consensus.Signer（secp256k1，测试用）。
type devSigner struct{}

func (devSigner) Sign(digest types.Hash) (types.Signature, error) {
	full := crypto.Keccak256(digest.Bytes())
	var sig types.Signature
	copy(sig[:], full[:])
	return sig, nil
}

func (devSigner) Verify(digest types.Hash, sig types.Signature, _ types.Address) bool {
	// 测试 Signer：重算摘要对比（伪造检测）
	full := crypto.Keccak256(digest.Bytes())
	var want types.Signature
	copy(want[:], full[:])
	return sig == want
}

// buildQCEnv 构造 4 验证者环境：真实 secp256k1 签名 + BLS 聚合签名。
func buildQCEnv(t *testing.T) (*consensus.ValidatorSet, *blsSignerAdapter, func(h types.Height, r types.Round, qcType consensus.VoteType, bh types.Hash) *consensus.QC) {
	t.Helper()

	const n = 4
	vals := make([]consensus.Validator, 0, n)
	keys := make(map[types.Address]*cbls.SecretKey)
	for i := 0; i < n; i++ {
		seed := []byte{byte(i + 1), 0xAA}
		sk, err := cbls.KeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		// 地址与 secp256k1 dev 派生一致（复用同一种子规则）
		buf := make([]byte, 32)
		for j := range buf {
			buf[j] = byte(i + 1)
		}
		full := crypto.Keccak256(buf)
		addr := types.Address{full[12], full[13], full[14], full[15], full[16],
			full[17], full[18], full[19], full[20], full[21],
			full[22], full[23], full[24], full[25], full[26],
			full[27], full[28], full[29], full[30], full[31]}
		vals = append(vals, consensus.Validator{Address: addr, Power: 1})
		keys[addr] = sk
	}
	valSet := consensus.NewValidatorSet(vals)
	adapter := &blsSignerAdapter{keys: keys}

	// QC 构造器：位图 + 逐个 secp256k1 签名 + BLS 聚合签名
	build := func(h types.Height, r types.Round, qcType consensus.VoteType, bh types.Hash) *consensus.QC {
		v := consensus.Vote{Type: qcType, BlockHash: bh}
		digest := consensus.VoteDigest(h, r, v)

		qc := &consensus.QC{
			Type: qcType, Height: h, Round: r, BlockHash: bh,
		}
		// 位图 + BLS 聚合
		bitmap := make([]byte, (n+7)/8)
		blsSigs := make([]cbls.Signature, 0, n)
		for i := 0; i < n; i++ {
			val, _ := valSet.At(i)
			addr := val.Address
			bitmap[i/8] |= 1 << (i % 8)

			// secp256k1 占位签名（本测试只验证 BLS 聚合路径，
			// Signatures 是位图一致性与证据材料）
			secpSig := types.Signature{}
			secpSig[0] = byte(i + 1)
			qc.Signatures = append(qc.Signatures, consensus.QCSignature{
				Validator: addr, Sig: secpSig,
			})

			blsSigs = append(blsSigs, keys[addr].Sign(digest.Bytes()))
		}
		qc.AggBitmap = bitmap
		agg, err := cbls.Aggregate(blsSigs)
		if err != nil {
			t.Fatal(err)
		}
		qc.AggSig = agg
		return qc
	}
	return valSet, adapter, build
}

// TestVerifyQCBLS_HappyPath 4 验证者全签名的 BLS 聚合 QC 验证通过。
func TestVerifyQCBLS_HappyPath(t *testing.T) {
	valSet, adapter, build := buildQCEnv(t)

	self, _ := valSet.At(0)
	cfg := consensus.Config{
		Self:       self.Address,
		Validators: valSet,
		Signer:     devSigner{},
		BLSSigner:  adapter,
	}
	st, err := consensus.NewState(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	bh := types.Hash(crypto.Keccak256([]byte("block-1")))
	qc := build(1, 0, consensus.Prevote, bh)

	if !st.VerifyQC(qc) {
		t.Fatal("BLS 聚合 QC 应通过验证")
	}
}

// TestVerifyQCBLS_BitmapTamper 位图与签名列表不一致 → 拒绝。
func TestVerifyQCBLS_BitmapTamper(t *testing.T) {
	valSet, adapter, build := buildQCEnv(t)

	self, _ := valSet.At(0)
	cfg := consensus.Config{
		Self:       self.Address,
		Validators: valSet,
		Signer:     devSigner{},
		BLSSigner:  adapter,
	}
	st, _ := consensus.NewState(cfg, nil, nil)

	bh := types.Hash(crypto.Keccak256([]byte("block-2")))
	qc := build(1, 0, consensus.Precommit, bh)

	// 篡改位图：多打开一位（地址集合与 Signatures 不再一致）
	tampered := *qc
	tampered.AggBitmap = append([]byte{}, qc.AggBitmap...)
	tampered.AggBitmap[0] |= 0x80
	if st.VerifyQC(&tampered) {
		t.Fatal("位图与签名列表不一致应拒绝")
	}

	// 位图清零一位（少一个签名者 → 数量不符）→ 拒绝
	tampered2 := *qc
	tampered2.AggBitmap = append([]byte{}, qc.AggBitmap...)
	tampered2.AggBitmap[0] &= 0xFE
	if st.VerifyQC(&tampered2) {
		t.Fatal("位图数量与签名数量不一致应拒绝")
	}
}

// TestVerifyQCBLS_AggSigTamper 聚合签名被篡改 → 拒绝。
func TestVerifyQCBLS_AggSigTamper(t *testing.T) {
	valSet, adapter, build := buildQCEnv(t)

	self, _ := valSet.At(0)
	cfg := consensus.Config{
		Self:       self.Address,
		Validators: valSet,
		Signer:     devSigner{},
		BLSSigner:  adapter,
	}
	st, _ := consensus.NewState(cfg, nil, nil)

	bh := types.Hash(crypto.Keccak256([]byte("block-3")))
	qc := build(1, 0, consensus.Prevote, bh)

	tampered := *qc
	tampered.AggSig = append([]byte{}, qc.AggSig...)
	tampered.AggSig[10] ^= 0xff
	if st.VerifyQC(&tampered) {
		t.Fatal("被篡改的聚合签名应拒绝")
	}
}

// TestVerifyQCBLS_QuorumNotMet 签名数量不足 → 拒绝。
func TestVerifyQCBLS_QuorumNotMet(t *testing.T) {
	valSet, adapter, build := buildQCEnv(t)

	self, _ := valSet.At(0)
	cfg := consensus.Config{
		Self:       self.Address,
		Validators: valSet,
		Signer:     devSigner{},
		BLSSigner:  adapter,
	}
	st, _ := consensus.NewState(cfg, nil, nil)

	bh := types.Hash(crypto.Keccak256([]byte("block-4")))
	qc := build(1, 0, consensus.Prevote, bh)

	// 4 个验证者 quorum=3；只保留 2 个签名 → 数量不足
	qc.Signatures = qc.Signatures[:2]
	bitmap := make([]byte, 1)
	bitmap[0] = 0x03 // 2 位
	qc.AggBitmap = bitmap
	qc.AggSig = make([]byte, 48) // 空签名走不到 BLS 验证（数量先拦截）

	if st.VerifyQC(qc) {
		t.Fatal("签名数量不足应拒绝")
	}
}
