package bls_test

import (
	"testing"

	"github.com/chfault/chfault/crypto/bls"
)

// TestKeyGenDeterministic 验证密钥派生的确定性（同种子同公钥 —— 验证者集的身份基础）。
func TestKeyGenDeterministic(t *testing.T) {
	sk1, err := bls.KeyGen([]byte("validator-1"))
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := bls.KeyGen([]byte("validator-1"))
	if err != nil {
		t.Fatal(err)
	}

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()
	if string(pk1) != string(pk2) {
		t.Fatal("同种子派生的公钥不同（确定性被破坏）")
	}
	if len(pk1) != bls.PublicKeyLen {
		t.Fatalf("公钥长度应为 %d，实际 %d", bls.PublicKeyLen, len(pk1))
	}

	// 不同种子 → 不同公钥
	sk3, _ := bls.KeyGen([]byte("validator-2"))
	if string(sk3.PublicKey()) == string(pk1) {
		t.Fatal("不同种子派生出相同公钥")
	}
}

// TestSignVerify 单签名往返。
func TestSignVerify(t *testing.T) {
	sk, _ := bls.KeyGen([]byte("v1"))
	pk := sk.PublicKey()

	msg := []byte("chfault-vote" + "block-hash-001")
	sig := sk.Sign(msg)

	if len(sig) != bls.SignatureLen {
		t.Fatalf("签名长度应为 %d，实际 %d", bls.SignatureLen, len(sig))
	}
	if !bls.Verify(pk, msg, sig) {
		t.Fatal("有效签名应通过验证")
	}
	if bls.Verify(pk, []byte("tampered"), sig) {
		t.Fatal("篡改的消息应验证失败")
	}

	// 错误的公钥
	sk2, _ := bls.KeyGen([]byte("v2"))
	if bls.Verify(sk2.PublicKey(), msg, sig) {
		t.Fatal("错误公钥应验证失败")
	}
}

// TestAggregate_FastVerify 聚合签名核心场景 —— QC：
// n 个验证者对**同一 digest** 投票 → 聚合成 1 个签名 → 一次配对验证。
func TestAggregate_FastVerify(t *testing.T) {
	const n = 4
	msg := []byte("chfault-vote-height-7-round-2-block-abc")

	sks := make([]*bls.SecretKey, 0, n)
	pks := make([]bls.PublicKey, 0, n)
	sigs := make([]bls.Signature, 0, n)
	for i := 0; i < n; i++ {
		seed := []byte{byte(i + 1), 0xde, 0xad}
		sk, err := bls.KeyGen(seed)
		if err != nil {
			t.Fatal(err)
		}
		sks = append(sks, sk)
		pks = append(pks, sk.PublicKey())
		sigs = append(sigs, sk.Sign(msg))
	}

	aggSig, err := bls.Aggregate(sigs)
	if err != nil {
		t.Fatalf("聚合失败: %v", err)
	}
	if len(aggSig) != bls.SignatureLen {
		t.Fatalf("聚合签名长度应仍为 %d（QC O(1) 的关键），实际 %d",
			bls.SignatureLen, len(aggSig))
	}

	if !bls.FastAggregateVerify(pks, msg, aggSig) {
		t.Fatal("聚合签名应通过快速验证")
	}

	// 混入一个无效签名者 → 失败
	outsider, _ := bls.KeyGen([]byte("outsider"))
	badPKs := append(append([]bls.PublicKey{}, pks...), outsider.PublicKey())
	if bls.FastAggregateVerify(badPKs, msg, aggSig) {
		t.Fatal("混入局外公钥后应验证失败")
	}

	// 篡改消息 → 失败
	if bls.FastAggregateVerify(pks, []byte("other msg"), aggSig) {
		t.Fatal("不同消息应验证失败")
	}
}

// TestAggregateVerify_MultiMessage 多消息聚合验证（备用 API）。
func TestAggregateVerify_MultiMessage(t *testing.T) {
	const n = 3
	pks := make([]bls.PublicKey, 0, n)
	msgs := make([][]byte, 0, n)
	sigs := make([]bls.Signature, 0, n)
	for i := 0; i < n; i++ {
		sk, _ := bls.KeyGen([]byte{byte(i + 1), 0xbe, 0xef})
		m := []byte{byte(i)}
		pks = append(pks, sk.PublicKey())
		msgs = append(msgs, m)
		sigs = append(sigs, sk.Sign(m))
	}

	aggSig, err := bls.Aggregate(sigs)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.AggregateVerify(pks, msgs, aggSig) {
		t.Fatal("多消息聚合验证应通过")
	}

	// 消息错位 → 失败
	swapped := [][]byte{msgs[1], msgs[0], msgs[2]}
	if bls.AggregateVerify(pks, swapped, aggSig) {
		t.Fatal("消息错位后应验证失败")
	}
}

// TestAggregate_SingleAndEmpty 边界：单签名聚合 = 原签名；空列表报错。
func TestAggregate_SingleAndEmpty(t *testing.T) {
	sk, _ := bls.KeyGen([]byte("solo"))
	msg := []byte("single")
	sig := sk.Sign(msg)

	one, err := bls.Aggregate([]bls.Signature{sig})
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(sig) {
		t.Fatal("单签名聚合应等于原签名")
	}

	if _, err := bls.Aggregate(nil); err == nil {
		t.Fatal("空聚合应报错")
	}
	if bls.FastAggregateVerify(nil, msg, sig) {
		t.Fatal("空公钥列表应验证失败")
	}
}

// TestInvalidSignatureRejected 垃圾签名被结构化拒绝。
func TestInvalidSignatureRejected(t *testing.T) {
	sk, _ := bls.KeyGen([]byte("v"))
	pk := sk.PublicKey()

	if bls.Verify(pk, []byte("m"), bls.Signature(make([]byte, 10))) {
		t.Fatal("长度错误的签名应拒绝")
	}
	if bls.Verify(pk, []byte("m"), bls.Signature(make([]byte, 48))) {
		t.Fatal("全零签名应拒绝（不在子群/无效点）")
	}
	if _, err := bls.Aggregate([]bls.Signature{make([]byte, 48)}); err == nil {
		t.Fatal("聚合垃圾签名应报错")
	}
}
