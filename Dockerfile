# Railway 用 Dockerfile（Deno 2 模板，Railway 默认的 Deno 1 不可用）
FROM denoland/deno:2.9.5

WORKDIR /app

# 只复制运行时必需文件，保持层缓存
COPY deno.json ./
COPY src/ ./src/

# Railway 注入 PORT，必须监听 0.0.0.0
EXPOSE 8000

CMD ["run", "--allow-net", "--allow-env", "src/index.ts"]
