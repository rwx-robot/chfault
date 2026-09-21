package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// cmdSnapshot 管理链数据快照。
//
// 用法：
//
//	chfault snapshot create --data ./data --out ./snap
//	chfault snapshot restore --snap ./snap --data ./data-restored
//
// 实现：直接复制数据目录（v0 数据量为 MB 级，复制即可秒级完成）。
// Pebble 的 Checkpoint 在 v1.17 中对硬链接的目标目录有额外约束
// （实测：OPTIONS 文件 link 失败），直接复制更简单可靠 ——
// M2 数据量增大时评估是否切回 Checkpoint。
//
// ⚠️ create 时节点必须已停止（或至少不在写块）—— 快照一致性依赖此约束。
func cmdSnapshot(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: chfault snapshot <create|restore> [flags]")
	}

	switch args[0] {
	case "create":
		return snapshotCreate(args[1:])
	case "restore":
		return snapshotRestore(args[1:])
	default:
		return fmt.Errorf("未知子命令: %s（支持 create / restore）", args[0])
	}
}

func snapshotCreate(args []string) error {
	fs := flag.NewFlagSet("snapshot create", flag.ExitOnError)
	data := fs.String("data", "./data", "数据目录（含 db/）")
	out := fs.String("out", "./snapshot", "快照输出目录")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dbPath := filepath.Join(*data, "db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("数据目录不存在或不可读: %s（节点必须在停止状态下创建快照）", dbPath)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("快照目录已存在: %s（拒绝覆盖）", *out)
	}

	if err := copyDir(dbPath, *out); err != nil {
		return fmt.Errorf("创建快照失败: %w", err)
	}

	fmt.Printf("✅ 快照已创建: %s → %s\n", dbPath, *out)
	fmt.Println("   恢复: chfault snapshot restore --snap " + *out + " --data <new-dir>")
	return nil
}

func snapshotRestore(args []string) error {
	fs := flag.NewFlagSet("snapshot restore", flag.ExitOnError)
	snap := fs.String("snap", "./snapshot", "快照目录")
	data := fs.String("data", "./data-restored", "目标数据目录")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*snap); err != nil {
		return fmt.Errorf("快照目录不存在: %s", *snap)
	}
	if _, err := os.Stat(*data); err == nil {
		return fmt.Errorf("目标目录已存在: %s（拒绝覆盖）", *data)
	}

	if err := copyDir(*snap, *data); err != nil {
		return fmt.Errorf("恢复失败: %w", err)
	}

	fmt.Printf("✅ 已恢复到: %s\n", *data)
	fmt.Println("   启动: chfault start --config <config>（storage.dataDir 指向该目录）")
	return nil
}

// copyDir 递归复制目录。
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)
	return err
}
