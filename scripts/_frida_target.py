#!/usr/bin/env python3
"""Frida 验证目标进程 — 模拟 Agent 的工具调用行为"""
import os
import subprocess
import time


def main():
    print(f"_frida_target pid={os.getpid()}", flush=True)
    for i in range(6):
        subprocess.run(["echo", f"hello_{i}"], capture_output=True)
        time.sleep(1)
    print("_frida_target done", flush=True)


if __name__ == "__main__":
    main()
