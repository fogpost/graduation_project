#!/bin/bash

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

# 启动后端
gnome-terminal -- bash -c "$REPO_ROOT/scripts/start_backend.sh; exec bash"

# 启动前端
gnome-terminal -- bash -c "$REPO_ROOT/scripts/start_frontend.sh; exec bash"

# 可选抓包
if [ "$1" == "--capture" ]; then
  gnome-terminal -- bash -c "$REPO_ROOT/scripts/start_go_capture.sh; exec bash"
fi

echo "Backend & frontend started"