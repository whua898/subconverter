#!/bin/bash
# Subconverter 自动部署脚本
set -e

echo "=== Subconverter 自动部署脚本 ==="
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"

# 配置
IMAGE_NAME="${DOCKER_IMAGE:-whua898/subconverter}"
CONTAINER_NAME="${CONTAINER_NAME:-subconverter}"
HOST_PORT="${HOST_PORT:-8080}"
CONFIG_MOUNT="${CONFIG_MOUNT:-$(pwd)/Base:/base}"

echo ""
echo "[1/5] 拉取最新 Docker 镜像..."
docker pull "$IMAGE_NAME"

echo ""
echo "[2/5] 停止并删除旧容器..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo ""
echo "[3/5] 启动新容器..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "$HOST_PORT":80 \
  -v "$CONFIG_MOUNT" \
  --restart=unless-stopped \
  "$IMAGE_NAME"

echo ""
echo "[4/5] 等待服务就绪（5秒）..."
sleep 5

echo ""
echo "[5/5] 检查容器状态..."
if docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" | grep -q "$CONTAINER_NAME"; then
    echo "✓ 容器运行正常"
    echo "  容器ID: $(docker ps --filter "name=$CONTAINER_NAME" --format "{{.ID}}" | head -1)"
    echo "  端口映射: $HOST_PORT:80"
else
    echo "✗ 容器启动失败，查看日志："
    docker logs "$CONTAINER_NAME" --tail 20
    exit 1
fi

echo ""
echo "=== 部署完成 ==="
echo "服务地址: http://localhost:$HOST_PORT"