package main

import (
	"bytes"
	"gopkg.in/yaml.v3"
)

// yamlMarshalImpl 是 yamlMarshal 的实际实现。
//
// yaml.Marshal 对 struct 按字段声明顺序输出，顺序稳定，无需额外处理。
func yamlMarshalImpl(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
