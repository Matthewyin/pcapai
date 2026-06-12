#!/bin/bash
# 双击启动 pcapAI（本地 web app 模式）。首次使用：在 Finder 右键此文件 → 打开。
cd "$(dirname "$0")" || exit 1
exec npm run launch
