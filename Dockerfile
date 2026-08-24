FROM denoland/deno:alpine-2.9.5

WORKDIR /app

COPY deno.json ./
COPY src/ ./src/

# 预缓存依赖，加速启动
RUN deno cache src/index.ts

EXPOSE 8000

# Railway 注入 PORT，需监听 0.0.0.0:$PORT
CMD ["run", "--allow-net", "--allow-env", "src/index.ts"]
