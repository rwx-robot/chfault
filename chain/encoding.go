package chain

import (
	"encoding/binary"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// beUint64 编码 uint64 为大端 8 字节。
//
// 独立实现（而非直接调用 crypto.Uint64BE）是为了让 chain 包
// 在热路径上避免额外的包调用开销；语义与 crypto 完全一致。
func beUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// cryptoKeccak256 是 crypto.Keccak256 的薄封装。
func cryptoKeccak256(data ...[]byte) types.Hash {
	return crypto.Keccak256(data...)
}
