package chain

import (
	"encoding/binary"
	"fmt"

	"github.com/chfault/chfault/types"
)

// Receipt 的编解码（spec/30）。
//
// 布局：
//
//	receipt = status(1) ‖ tx_hash(32) ‖ gas_used(8BE) ‖ cumulative_gas_used(8BE)
//	          ‖ logs_bloom(256) ‖ effective_gas_price(32)
//	          ‖ has_contract_addr(1) [ ‖ contract_addr(20) ]
//	          ‖ log_count(4LE) ‖ (log)*
//
//	log = address(20) ‖ topic_count(1) ‖ topic(32)* ‖ data_len(8BE) ‖ data
//
// 定长字段用大端，变长集合的元素数量用小端（与区块体的长度前缀一致）。

// Encode 序列化收据。
func (r *Receipt) Encode() ([]byte, error) {
	if r.Status > 1 {
		return nil, fmt.Errorf("%w: status 必须是 0 或 1，实际 %d", ErrCodec, r.Status)
	}
	if r.LogsBloom != (types.Bloom{}) && r.LogsBloom != r.ComputeLogsBloom() {
		// 允许显式设置的 bloom 与日志不一致？不允许 —— 那会导致索引错误。
		return nil, fmt.Errorf("%w: logs_bloom 与日志内容不一致", ErrCodec)
	}

	buf := make([]byte, 0, 512)
	buf = append(buf, r.Status)
	buf = append(buf, r.TxHash[:]...)
	buf = append(buf, beUint64(uint64(r.GasUsed))...)
	buf = append(buf, beUint64(uint64(r.CumulativeGasUsed))...)
	buf = append(buf, r.LogsBloom[:]...)
	buf = append(buf, r.EffectiveGasPrice[:]...)

	if r.ContractAddress != nil {
		buf = append(buf, 1)
		buf = append(buf, r.ContractAddress[:]...)
	} else {
		buf = append(buf, 0)
	}

	if len(r.Logs) > 0xffffffff {
		return nil, fmt.Errorf("%w: 日志数量过多", types.ErrOversized)
	}
	buf = append(buf, leUint32(uint32(len(r.Logs)))...)

	for i, lg := range r.Logs {
		if len(lg.Topics) > 4 {
			return nil, fmt.Errorf("%w: 日志 %d 的 topics 超过 4 个（EVM 限制）", ErrCodec, i)
		}
		buf = append(buf, lg.Address[:]...)
		buf = append(buf, byte(len(lg.Topics)))
		for _, t := range lg.Topics {
			buf = append(buf, t[:]...)
		}
		buf = append(buf, beUint64(uint64(len(lg.Data)))...)
		buf = append(buf, lg.Data...)
	}

	return buf, nil
}

// DecodeReceipt 反序列化收据。
func DecodeReceipt(data []byte) (*Receipt, error) {
	const minSize = 1 + 32 + 8 + 8 + 256 + 32 + 1 + 4
	if len(data) < minSize {
		return nil, fmt.Errorf("%w: 收据需要至少 %d 字节，实际 %d", ErrCodec, minSize, len(data))
	}

	r := &Receipt{}
	pos := 0
	take := func(n int) []byte {
		b := data[pos : pos+n]
		pos += n
		return b
	}

	r.Status = take(1)[0]
	if r.Status > 1 {
		return nil, fmt.Errorf("%w: status 必须是 0 或 1，实际 %d", ErrCodec, r.Status)
	}
	copy(r.TxHash[:], take(32))
	r.GasUsed = types.Gas(binary.BigEndian.Uint64(take(8)))
	r.CumulativeGasUsed = types.Gas(binary.BigEndian.Uint64(take(8)))
	copy(r.LogsBloom[:], take(256))
	copy(r.EffectiveGasPrice[:], take(32))

	hasContract := take(1)[0]
	if hasContract == 1 {
		var addr types.Address
		copy(addr[:], take(20))
		r.ContractAddress = &addr
	} else if hasContract != 0 {
		return nil, fmt.Errorf("%w: contract_address 标志位非法: %d", ErrCodec, hasContract)
	}

	logCount := binary.LittleEndian.Uint32(take(4))
	// 防御：日志数量上限（每条日志至少 20+1+8 = 29 字节）
	if logCount > uint32(len(data)/29)+1 {
		return nil, fmt.Errorf("%w: 日志数量 %d 不合理", ErrCodec, logCount)
	}

	r.Logs = make([]*Log, 0, logCount)
	for i := uint32(0); i < logCount; i++ {
		if len(data)-pos < 20+1+8 {
			return nil, fmt.Errorf("%w: 第 %d 条日志被截断", ErrCodec, i)
		}
		lg := &Log{}
		copy(lg.Address[:], take(20))
		topicCount := int(take(1)[0])
		if topicCount > 4 {
			return nil, fmt.Errorf("%w: 第 %d 条日志 topics 数量 %d 超过 4", ErrCodec, i, topicCount)
		}
		if len(data)-pos < topicCount*32+8 {
			return nil, fmt.Errorf("%w: 第 %d 条日志的 topics 被截断", ErrCodec, i)
		}
		lg.Topics = make([]types.Hash, topicCount)
		for j := 0; j < topicCount; j++ {
			copy(lg.Topics[j][:], take(32))
		}
		dataLen := binary.BigEndian.Uint64(take(8))
		if uint64(len(data)-pos) < dataLen {
			return nil, fmt.Errorf("%w: 第 %d 条日志的 data 被截断", ErrCodec, i)
		}
		lg.Data = append([]byte(nil), take(int(dataLen))...)
		r.Logs = append(r.Logs, lg)
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: 收据解析后仍有 %d 字节剩余", ErrCodec, len(data)-pos)
	}
	return r, nil
}

// HashTreeRoot 计算收据的哈希树根（用于 receipt_root）。
func (r *Receipt) HashTreeRoot() types.Hash {
	return receiptLeaf(r)
}
