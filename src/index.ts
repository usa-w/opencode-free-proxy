/**
 * 免费模型反向代理（双上游，跨运行时：Cloudflare Workers / Deno / Node）
 *
 * 对外暴露 OpenAI 兼容 API：
 *   GET  /v1/models   ← 合并两上游免费列表
 *   POST /v1/chat/completions ← 仅允许免费模型，SSE 流式透传
 *
 * 上游 1「zen」：https://opencode.ai/zen/v1（默认路由，裸模型 ID）
 *   免费通道要求伪装官方 opencode CLI 指纹头 + Authorization: Bearer public；
 *   模型 ID 原样透传（免费模型自带 -free 后缀，另有 stealth 免费模型 big-pickle）。
 *
 * 上游 2「cline」：https://api.cline.bot/api/v1（模型 ID 加 cline/ 前缀路由）
 *   需在 app.cline.bot 注册并生成 API Key（env.CLINE_KEY），
 *   请求头必须携带 x-client-type: cline-cli；
 *   免费模型清单来自匿名端点 /ai/cline/recommended-models 的 .free[]。
 */

interface Env {
  API_KEY: string;
  /** 可选：自己的 OpenCode Zen key（BYOK），绕开匿名共享池限流 */
  ZEN_KEY?: string;
  /** Cline 免费模型的访问 Key（app.cline.bot 注册获取）；调用 cline/* 模型时必填 */
  CLINE_KEY?: string;
  /** 可选：设为 "0" 关闭模型故障转移（默认开启） */
  FALLBACK?: string;
}

type UpstreamId = "zen" | "cline";

/** 模型请求解析结果：externalId 为对外完整 ID，upstreamModelId 为发往上游的真实 ID */
interface ModelRoute {
  upstream: UpstreamId;
  externalId: string;
  upstreamModelId: string;
}

const UPSTREAM_BASE = "https://opencode.ai/zen/v1";
const CLINE_BASE = "https://api.cline.bot/api/v1";
const CLINE_PREFIX = "cline/";
const CLI_UA = "opencode/1.18.31 ai-sdk/provider-utils/4.0.40 runtime/bun/1.3.14";
const MODELS_CACHE_TTL_MS = 5 * 60 * 1000;

/** zen 上游拉取失败时的兜底免费模型清单（同步自上游实测 2026-09） */
const FALLBACK_ZEN_FREE_MODELS: ReadonlyArray<string> = [
  "jev-1.13-free",
  "deepseek-v4-flash-free",
  "muse-spark-1.3-contributor-free",
  "muse-spark-1.2-contributor-free",
  "mimo-v2.5-free",
  "ling-3.0-flash-fin-free",
  "nemotron-3-ultra-free",
  "nemotron-3.5-lightning-free",
];

/** cline 上游拉取失败时的兜底免费模型清单（同步自 recommended-models 实测） */
const FALLBACK_CLINE_FREE_MODELS: ReadonlyArray<string> = [
  "cline-free/muse-spark-1.3-contributor",
  "deepseek/deepseek-v4-flash",
  "z-ai/glm-5.3-flash",
  "cline-free/solar-pro4",
  "cline-free/longcat-2.0",
  "poolside/laguna-s-2.1:free",
];

/** 解析对外模型 ID → 路由目标；带 cline/ 前缀走 cline 上游，其余走 zen */
function parseModelRoute(model: string): ModelRoute {
  if (model.startsWith(CLINE_PREFIX)) {
    return {
      upstream: "cline",
      externalId: model,
      upstreamModelId: model.slice(CLINE_PREFIX.length),
    };
  }
  return { upstream: "zen", externalId: model, upstreamModelId: model };
}

/** 上游真实 ID ↔ 对外 ID 映射（cline 统一加前缀） */
function toExternalId(upstream: UpstreamId, upstreamModelId: string): string {
  return upstream === "zen" ? upstreamModelId : CLINE_PREFIX + upstreamModelId;
}

/** 不带 -free 后缀但当前免费的模型（stealth 免费模型） */
const FREE_WITHOUT_SUFFIX = new Set<string>(["big-pickle"]);

function isFreeModelId(id: string): boolean {
  return id.endsWith("-free") || FREE_WITHOUT_SUFFIX.has(id);
}

/** 模型清单缓存（按 isolate 存活周期） */
let zenModelsCache: { ids: string[]; fetchedAt: number } | null = null;
let clineModelsCache: { ids: string[]; fetchedAt: number } | null = null;

function jsonHeaders(): Headers {
  const h = new Headers();
  h.set("content-type", "application/json");
  h.set("access-control-allow-origin", "*");
  return h;
}

function openaiError(message: string, type: string, code: string | null, status: number): Response {
  return new Response(
    JSON.stringify({ error: { message, type, param: null, code } }),
    { status, headers: jsonHeaders() },
  );
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 校验 Bearer 密钥（两侧哈希后比较） */
async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return false;
  const given = await sha256Hex(auth.slice("Bearer ".length));
  const expected = await sha256Hex(env.API_KEY);
  return given === expected;
}

/** OpenCode ID 生成（i-code v0.3.8 对齐：snowflake 时间戳 + base62 随机，非 UUID）
 * 算法：v = (now_ms % 2^36) * 4096 + ctr；session 取反；低 48 位 → 12 hex；+ 14 base62
 * 上游只校验低 36 位时间戳（now_ms % 2^36），通过 (id >> 12) 还原
 */
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const MS_MOD = 1n << 36n; // 2^36
let opencodeCtr = 0;
let opencodeLastMs = 0;

function generateOpencodeId(negate: boolean): string {
  const nowMs = Date.now();
  if (opencodeLastMs !== nowMs) {
    opencodeLastMs = nowMs;
    opencodeCtr = 1;
  } else {
    opencodeCtr++;
  }
  // 只保留低 36 位毫秒（与上游校验逻辑一致）
  const msLow36 = BigInt(nowMs) % MS_MOD;
  let v = msLow36 * 4096n + BigInt(opencodeCtr);
  if (negate) v = ~v;
  // 低 48 位 → 12 hex
  const low48 = v & 0xFFFF_FFFF_FFFFFn;
  const tsPart = low48.toString(16).padStart(12, "0");
  // 14 base62 随机
  const arr = new Uint8Array(14);
  crypto.getRandomValues(arr);
  let randPart = "";
  for (const b of arr) randPart += BASE62[b % 62];
  return tsPart + randPart;
}

/** 会话 ID：当天固定（ses_ 前缀） */
let dailySessionCache: { day: string; id: string } | null = null;
function dailySessionId(): string {
  const day = new Date().toISOString().slice(0, 10);
  if (dailySessionCache && dailySessionCache.day === day) return dailySessionCache.id;
  const id = `ses_${generateOpencodeId(true)}`;
  dailySessionCache = { day, id };
  return id;
}

/** 请求 ID：每次刷新（msg_ 前缀） */
function requestId(): string {
  return `msg_${generateOpencodeId(false)}`;
}

/**
 * 构造上游请求头：伪装官方 opencode CLI 指纹（i-code v0.3.8 合规）。
 * 认证：优先 BYOK（env.ZEN_KEY），否则匿名 `Bearer public`（受共享池限流）。
 * - x-opencode-session：按天固定（同一天不变）
 * - x-opencode-request：每次请求新生成
 */
function buildUpstreamHeaders(authKey: string | undefined, bodySize?: number): Headers {
  const h = new Headers();
  if (bodySize !== undefined) {
    h.set("content-type", "application/json");
    h.set("content-length", String(bodySize));
  }
  h.set("authorization", authKey ? `Bearer ${authKey}` : "Bearer public");
  h.set("user-agent", CLI_UA);
  h.set("accept", "*/*");
  h.set("x-opencode-client", "cli");
  h.set("x-opencode-project", "global");
  h.set("x-opencode-session", dailySessionId());
  h.set("x-opencode-request", requestId());
  return h;
}

/** cline 上游请求头：账号 Key + CLI 客户端标识 */
function buildClineHeaders(apiKey: string, bodySize?: number): Headers {
  const h = new Headers();
  if (bodySize !== undefined) {
    h.set("content-type", "application/json");
    h.set("content-length", String(bodySize));
  }
  h.set("authorization", `Bearer ${apiKey}`);
  h.set("accept", "*/*");
  h.set("x-client-type", "cline-cli");
  return h;
}

/** 拉取 zen 上游免费模型清单（带内存缓存；失败回退静态清单） */
async function getZenFreeModelIds(authKey: string | undefined): Promise<string[]> {
  if (zenModelsCache && Date.now() - zenModelsCache.fetchedAt < MODELS_CACHE_TTL_MS) {
    return zenModelsCache.ids;
  }
  try {
    const resp = await fetch(`${UPSTREAM_BASE}/models`, { headers: buildUpstreamHeaders(authKey) });
    if (!resp.ok) throw new Error(`status ${resp.status}`);
    const data = (await resp.json()) as { data?: Array<{ id?: string }> };
    const ids = (data.data ?? [])
      .map((m) => m.id ?? "")
      .filter((id) => id.length > 0 && isFreeModelId(id));
    if (ids.length === 0) throw new Error("no free models in upstream list");
    zenModelsCache = { ids, fetchedAt: Date.now() };
    return ids;
  } catch {
    // 回退到静态清单，不写缓存以便下次重试
    return [...FALLBACK_ZEN_FREE_MODELS];
  }
}

/**
 * 拉取 cline 上游免费模型清单。
 * 免费列表端点可匿名访问：GET /ai/cline/recommended-models → .free[].id
 */
async function getClineFreeModelIds(): Promise<string[]> {
  if (clineModelsCache && Date.now() - clineModelsCache.fetchedAt < MODELS_CACHE_TTL_MS) {
    return clineModelsCache.ids;
  }
  try {
    const resp = await fetch(`${CLINE_BASE}/ai/cline/recommended-models`);
    if (!resp.ok) throw new Error(`status ${resp.status}`);
    const data = (await resp.json()) as { free?: Array<{ id?: string }> };
    const ids = (data.free ?? [])
      .map((m) => m.id ?? "")
      .filter((id) => id.length > 0);
    if (ids.length === 0) throw new Error("no free models in cline list");
    clineModelsCache = { ids, fetchedAt: Date.now() };
    return ids;
  } catch {
    return [...FALLBACK_CLINE_FREE_MODELS];
  }
}

function listUpstreamFreeIds(upstream: UpstreamId, env: Env): Promise<string[]> {
  return upstream === "zen" ? getZenFreeModelIds(env.ZEN_KEY) : getClineFreeModelIds();
}

/** 模型健康缓存：上游故障的模型在 TTL 内被标记为不健康（按 isolate 存活周期） */
const UNHEALTHY_TTL_MS = 10 * 60 * 1000;
const modelHealth = new Map<string, number>();

function markUnhealthy(id: string): void {
  modelHealth.set(id, Date.now() + UNHEALTHY_TTL_MS);
}

function markHealthy(id: string): void {
  modelHealth.delete(id);
}

function isHealthy(id: string): boolean {
  const until = modelHealth.get(id);
  if (until === undefined) return true;
  if (Date.now() > until) {
    modelHealth.delete(id);
    return true;
  }
  return false;
}

/** 上游错误是否值得触发故障转移/健康标记（客户端错误除外） */
function isTransientUpstreamFailure(status: number, bodyText: string): boolean {
  if (status === 429 || status >= 500) return true;
  return /unavailable|Internal server error|FreeUsageLimit/i.test(bodyText);
}

async function handleModels(env: Env): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const sections: Array<{ upstream: UpstreamId; ids: string[] }> = [
    { upstream: "zen", ids: await getZenFreeModelIds(env.ZEN_KEY) },
    { upstream: "cline", ids: await getClineFreeModelIds() },
  ];

  const data: Array<{ id: string; object: string; created: number; owned_by: string }> = [];
  for (const section of sections) {
    let ids = section.ids;
    // 过滤当前已知不健康的模型；若全部不健康则保留完整列表（按上游分别判断）
    const healthy = ids.filter((id) => isHealthy(toExternalId(section.upstream, id)));
    if (healthy.length > 0) ids = healthy;
    for (const id of ids) {
      data.push({
        id: toExternalId(section.upstream, id),
        object: "model",
        created: now,
        owned_by: section.upstream === "zen" ? "opencode-zen-free" : "cline-free",
      });
    }
  }
  return new Response(JSON.stringify({ object: "list", data }), { headers: jsonHeaders() });
}

/** zen 上游合规化请求体（i-code v0.3.8 要求，代理侧自动兼容非流式）：
 * 1. 自动补 stream: true（上游仅接受流式；客户端非流式则代理聚合后还原）
 * 2. tools 必须存在、≥2 个且含 bash——缺失则自动注入最小化工具
 * 返回 { bodyText, wasStream } 供外层决定是否聚合
 */
function prepareZenBody(bodyText: string): { bodyText: string; wasStream: boolean } {
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(bodyText) as Record<string, unknown>;
  } catch {
    return { bodyText, wasStream: true }; // 非 JSON，按流式透传
  }

  const wasStream = body.stream === true;
  // 1. 上游强制流式：缺省/False 自动补 true，记录原值供聚合判断
  if (!wasStream) body.stream = true;

  // 2. tools 合规化
  const tools = body.tools;
  const toolsEmptyOrMissing = !Array.isArray(tools) || tools.length === 0;

  const minimalBash = {
    type: "function",
    function: { name: "bash", description: "x", parameters: { type: "object", properties: {}, required: [] }, strict: false },
  };
  const minimalRead = {
    type: "function",
    function: { name: "read", description: "x", parameters: { type: "object", properties: {}, required: [] }, strict: false },
  };

  if (toolsEmptyOrMissing) {
    body.tools = [minimalBash, minimalRead];
  } else {
    // 规范化扁平格式工具（旧版 {"type":"function","name":...} -> {"type":"function","function":{"name":...}}）
    const normalized = tools.map((t: unknown) => {
      const tool = t as Record<string, unknown>;
      if (tool.function) return tool; // 已是标准嵌套格式
      const name = tool.name as string | undefined;
      if (!name) return tool;
      const func: Record<string, unknown> = { name };
      if (tool.description) func.description = tool.description;
      if (tool.parameters) func.parameters = tool.parameters;
      if (tool.strict) func.strict = tool.strict;
      return { type: "function", function: func };
    });

    // 检查是否含 bash
    const hasBash = normalized.some((t: Record<string, unknown>) =>
      t.name === "bash" || (t.function as Record<string, unknown> | undefined)?.name === "bash"
    );

    let finalTools = normalized;
    if (!hasBash) finalTools = [minimalBash, ...finalTools];
    if (finalTools.length < 2) finalTools = [...finalTools, minimalRead];
    body.tools = finalTools;
  }

  return { bodyText: JSON.stringify(body), wasStream };
}

/** 将上游 SSE 流聚合成 OpenAI 非流式 JSON（供客户端 stream:false 时还原） */
async function aggregateSseToJson(sseText: string, fallbackModel: string): Promise<string> {
  const lines = sseText.split("\n");
  let content = "";
  let role: string | undefined;
  let id: string | undefined;
  let model: string | undefined;
  let finishReason: string | null = null;
  let usage: unknown | undefined;
  for (const line of lines) {
    const t = line.trim();
    if (!t.startsWith("data:")) continue;
    const data = t.slice(5).trim();
    if (data === "[DONE]") break;
    try {
      const j = JSON.parse(data) as Record<string, unknown>;
      if (!id && typeof j.id === "string") id = j.id as string;
      if (!model && typeof j.model === "string") model = j.model as string;
      const choices = (j.choices as Array<Record<string, unknown>> | undefined);
      const c0 = choices?.[0] as Record<string, unknown> | undefined;
      if (c0) {
        const delta = c0.delta as Record<string, unknown> | undefined;
        if (delta && typeof delta.content === "string") content += delta.content as string;
        if (delta && typeof delta.role === "string" && !role) role = delta.role as string;
        if (typeof c0.finish_reason === "string") finishReason = c0.finish_reason as string;
      }
      if (j.usage) usage = j.usage;
    } catch { /* ignore */ }
  }
  const now = Math.floor(Date.now() / 1000);
  return JSON.stringify({
    id: id ?? `chatcmpl-${crypto.randomUUID()}`,
    object: "chat.completion",
    created: now,
    model: model ?? fallbackModel,
    choices: [{ index: 0, message: { role: role ?? "assistant", content }, finish_reason: finishReason ?? "stop", logprobs: null }],
    usage: usage ?? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  });
}

/** 按上游构造转发目标与请求参数 */
function buildUpstreamPost(
  upstream: UpstreamId,
  env: Env,
  path: string,
  bodyText: string,
): { url: string; init: RequestInit } {
  if (upstream === "cline") {
    return {
      url: `${CLINE_BASE}${path}`,
      init: {
        method: "POST",
        headers: buildClineHeaders(env.CLINE_KEY as string, bodyText.length),
        body: bodyText,
      },
    };
  }
  // zen：应用合规化（强制流式 + tools 注入）；记录原 stream 供外层聚合判断
  const { bodyText: compliantBody, wasStream } = prepareZenBody(bodyText);
  return {
    url: `${UPSTREAM_BASE}${path}`,
    init: {
      method: "POST",
      headers: buildUpstreamHeaders(env.ZEN_KEY, compliantBody.length),
      body: compliantBody,
    },
    wasStream,
  } as { url: string; init: RequestInit; wasStream: boolean };
}

/**
 * Cline 上游非流式响应会把真实载荷包在顶层 `data` 字段里（{"data":{"choices":[...]}}），
 * 不符合 OpenAI 标准。此处剥壳：以 data 为准合并其余顶层字段后返回标准结构。
 * 非 JSON 或无包裹时原样返回。
 */
function unwrapClineEnvelope(text: string): string {
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const inner = parsed?.data;
    if (
      inner !== null &&
      typeof inner === "object" &&
      !Array.isArray(inner) &&
      Array.isArray((inner as { choices?: unknown }).choices)
    ) {
      const merged = { ...parsed, ...(inner as Record<string, unknown>) } as Record<string, unknown>;
      delete merged.data;
      return JSON.stringify(merged);
    }
  } catch {
    // 非 JSON，原样返回
  }
  return text;
}

async function handleChat(request: Request, env: Env): Promise<Response> {
  let parsed: { model?: unknown; stream?: unknown };
  try {
    parsed = JSON.parse(await request.text());
  } catch {
    return openaiError("Request body is not valid JSON.", "invalid_request_error", null, 400);
  }

  if (typeof parsed?.model !== "string" || parsed.model.length === 0) {
    return openaiError("'model' is required.", "invalid_request_error", null, 400);
  }

  // 路由：cline/ 前缀 → cline 上游；其余 → zen 上游
  const route = parseModelRoute(parsed.model);

  if (route.upstream === "cline" && !env.CLINE_KEY) {
    return openaiError(
      `Model '${parsed.model}' requires a Cline key. Register free at https://app.cline.bot, create an API key (Account -> API Keys), then set the CLINE_KEY environment variable.`,
      "invalid_request_error",
      "missing_upstream_key",
      400,
    );
  }

  // 仅放行免费模型，其余请求不触达上游
  const allowed = await listUpstreamFreeIds(route.upstream, env);
  if (!allowed.includes(route.upstreamModelId)) {
    const display = allowed.map((id) => toExternalId(route.upstream, id));
    return openaiError(
      `Model '${parsed.model}' not found or not free. Available: ${display.join(", ")}`,
      "invalid_request_error",
      "model_not_found",
      404,
    );
  }

  // 故障转移（限同一上游内）：请求的模型当前不健康时自动切换（可用 FALLBACK=0 关闭）
  let activeExternal: string = route.externalId;
  let activeModelId: string = route.upstreamModelId;
  const requestedUnhealthy = !isHealthy(activeExternal);
  let fallbackFrom: string | null = null;
  if (requestedUnhealthy && env.FALLBACK !== "0") {
    const candidate = allowed.find(
      (id) => id !== activeModelId && isHealthy(toExternalId(route.upstream, id)),
    );
    if (candidate) {
      fallbackFrom = activeExternal;
      activeModelId = candidate;
      activeExternal = toExternalId(route.upstream, candidate);
    }
  }
  parsed.model = activeModelId;

  const upstreamBody = JSON.stringify(parsed);

  const targetWithMeta = buildUpstreamPost(route.upstream, env, "/chat/completions", upstreamBody) as { url: string; init: RequestInit; wasStream?: boolean };
  const target: { url: string; init: RequestInit } = { url: targetWithMeta.url, init: targetWithMeta.init };
  const clientWantsStream = targetWithMeta.wasStream ?? (parsed.stream === true);
  let upstream: Response;
  try {
    upstream = await fetch(target.url, target.init);
  } catch (e) {
    markUnhealthy(activeExternal);
    return openaiError(`Upstream request failed: ${e instanceof Error ? e.message : "unknown"}`, "api_error", null, 502);
  }

  // 错误响应：标记健康状态；若为上游侧故障则尝试故障转移一次
  let errorText: string | null = null;
  if (!upstream.ok) {
    errorText = await upstream.text();
    if (isTransientUpstreamFailure(upstream.status, errorText)) {
      markUnhealthy(activeExternal);
      // 尚未转移过且未禁用转移 → 换一个健康模型重试
      if (!fallbackFrom && env.FALLBACK !== "0") {
        const candidate = allowed.find(
          (id) => id !== activeModelId && isHealthy(toExternalId(route.upstream, id)),
        );
        if (candidate) {
          fallbackFrom = activeExternal;
          activeModelId = candidate;
          activeExternal = toExternalId(route.upstream, candidate);
          parsed.model = candidate;
          try {
            const retryBody = JSON.stringify(parsed);
            const retryTargetRaw = buildUpstreamPost(route.upstream, env, "/chat/completions", retryBody) as { url: string; init: RequestInit; wasStream?: boolean };
            const retryTarget: { url: string; init: RequestInit } = { url: retryTargetRaw.url, init: retryTargetRaw.init };
            upstream = await fetch(retryTarget.url, retryTarget.init);
          } catch {
            return openaiError(`Upstream request failed during failover.`, "api_error", null, 502);
          }
        }
      }
    } else {
      markHealthy(activeExternal);
    }
    if (!upstream.ok) {
      const h = jsonHeaders();
      h.set("content-type", upstream.headers.get("content-type") ?? "application/json");
      return new Response(errorText, { status: upstream.status, headers: h });
    }
  } else {
    markHealthy(activeExternal);
  }

  const contentType = upstream.headers.get("content-type") ?? "application/json";

  const extraHeaders = new Headers();
  extraHeaders.set("access-control-allow-origin", "*");
  if (fallbackFrom !== null) {
    extraHeaders.set("x-model-fallback", `${fallbackFrom} -> ${activeExternal}`);
  }

  const isZen = route.upstream === "zen";
  const shouldStreamPassthrough = clientWantsStream && upstream.body !== null;

  // zen 非流式：上游恒为 SSE，需聚合还原为 JSON
  if (isZen && !clientWantsStream) {
    const sseText = await upstream.text();
    // 上游错误（非 2xx 已在上方处理），此处为成功 SSE，聚合后返回
    if (contentType.includes("text/event-stream") || sseText.includes("data:")) {
      const aggregated = await aggregateSseToJson(sseText, activeModelId);
      const h = jsonHeaders();
      for (const [k, v] of extraHeaders) h.set(k, v);
      return new Response(aggregated, { status: 200, headers: h });
    }
    // 非 SSE（如错误 JSON），直接透传
    const h = jsonHeaders();
    h.set("content-type", contentType);
    for (const [k, v] of extraHeaders) h.set(k, v);
    return new Response(sseText, { status: upstream.status, headers: h });
  }

  // 流式：SSE 字节流直接透传，不缓冲
  if (shouldStreamPassthrough) {
    const h = new Headers();
    h.set("content-type", contentType);
    h.set("cache-control", "no-cache");
    for (const [k, v] of extraHeaders) h.set(k, v);
    return new Response(upstream.body, { status: 200, headers: h });
  }

  // 非流式（cline 等）：透传 JSON（cline 上游需剥掉 data 包裹层，归一为标准 OpenAI 结构）
  let text = await upstream.text();
  if (route.upstream === "cline" && contentType.includes("application/json")) {
    text = unwrapClineEnvelope(text);
  }
  const h = jsonHeaders();
  h.set("content-type", contentType);
  for (const [k, v] of extraHeaders) h.set(k, v);
  return new Response(text, { status: upstream.status, headers: h });
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-max-age": "86400",
        },
      });
    }

    // 根路径信息页（免鉴权）
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        JSON.stringify({
          service: "opencode-free-proxy",
          upstreams: ["zen", "cline"],
          endpoints: ["/v1/models", "/v1/chat/completions"],
        }),
        { headers: jsonHeaders() },
      );
    }

    if (!(await isAuthorized(request, env))) {
      return openaiError(
        "Invalid or missing API key. Send 'Authorization: Bearer <key>'.",
        "invalid_request_error",
        "invalid_api_key",
        401,
      );
    }

    if (url.pathname === "/v1/models" && request.method === "GET") {
      return handleModels(env);
    }

    if (url.pathname === "/v1/chat/completions" && request.method === "POST") {
      return handleChat(request, env);
    }

    return openaiError(`Unknown endpoint: ${request.method} ${url.pathname}`, "invalid_request_error", null, 404);
  },
};

/**
 * 运行时自举：Deno 环境下直接启动服务，环境变量经 Deno.env 按请求读取。
 * Cloudflare Workers 中 globalThis.Deno 不存在，此分支不执行（由 Workers 运行时调用 fetch）。
 */
type DenoGlobal = {
  serve: (opts: {
    handler: (request: Request) => Promise<Response> | Response;
    port?: number;
    hostname?: string;
  }) => void;
  env: { get: (key: string) => string | undefined };
};

const denoGlobal = (globalThis as { Deno?: DenoGlobal }).Deno;

// 仅在直接运行（deno run）时自举
const isMain = (import.meta as unknown as { main?: boolean }).main;
if (denoGlobal && isMain) {
  const denoEnv: Env = {
    get API_KEY(): string {
      return denoGlobal.env.get("API_KEY") ?? "";
    },
    get ZEN_KEY(): string | undefined {
      return denoGlobal.env.get("ZEN_KEY") || undefined;
    },
    get CLINE_KEY(): string | undefined {
      return denoGlobal.env.get("CLINE_KEY") || undefined;
    },
    get FALLBACK(): string | undefined {
      return denoGlobal.env.get("FALLBACK") || undefined;
    },
  };
  const rawPort = denoGlobal.env.get("PORT");
  const port = Number(rawPort ?? "8000");
  console.log(
    `[opencode-free-proxy] PORT env="${rawPort ?? "(unset)"}" -> listening on 0.0.0.0:${port} ` +
      `(API_KEY=${denoEnv.API_KEY ? "set" : "missing"}, ZEN_KEY=${denoEnv.ZEN_KEY ? "set" : "public"}, CLINE_KEY=${denoEnv.CLINE_KEY ? "set" : "missing"})`,
  );
  denoGlobal.serve({
    handler: (request: Request) => worker.fetch(request, denoEnv),
    port,
    hostname: "0.0.0.0",
  });
}

export default worker;
