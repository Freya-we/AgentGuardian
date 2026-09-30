#!/usr/bin/env python3
"""生成 AgentGuardian 执行白名单配置文件条目

用法:
    scripts/gen_whitelist.py /usr/bin/python3 /bin/ls /usr/bin/git
    # 输出 sha256  path 行，可直接追加到 /etc/agent-guardian/exec_whitelist.conf
"""
import hashlib
import os
import sys


def compute_sha256(path: str) -> str:
    """计算文件的 SHA256 哈希，返回 64 字符 hex 字符串"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if len(sys.argv) < 2:
        print("用法: gen_whitelist.py <path1> [path2] ...", file=sys.stderr)
        print("输出格式: <sha256>  <path>", file=sys.stderr)
        sys.exit(1)

    exit_code = 0
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"# ERROR: 文件不存在: {path}", file=sys.stderr)
            exit_code = 1
            continue
        if os.path.isdir(path):
            print(f"# ERROR: 是目录: {path}", file=sys.stderr)
            exit_code = 1
            continue
        if os.path.islink(path):
            print(f"# ERROR: 是符号链接: {path}", file=sys.stderr)
            exit_code = 1
            continue

        try:
            sha = compute_sha256(path)
            print(f"{sha}  {path}")
        except PermissionError:
            print(f"# ERROR: 权限拒绝: {path}", file=sys.stderr)
            exit_code = 1
        except OSError as e:
            print(f"# ERROR: {path}: {e}", file=sys.stderr)
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
