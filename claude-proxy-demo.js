#!/usr/bin/env node
/*
 * claude-proxy-demo.js —— 本地「透明转发观察」代理
 *
 * 作用:把 Claude Code 发往 Anthropic API 的请求【逐字节】转发到 api.anthropic.com,
 *       同时把每个请求的结构打印出来,方便你亲眼验证前面的分析:
 *         - OAuth 订阅 + ANTHROPIC_BASE_URL 确实能一起工作(auth 头是 Bearer,不是 x-api-key)
 *         - 请求体里有 system 前缀 / metadata / betas(含 oauth-2025-04-20)
 *         - attestation 的 cch token 长什么样,且透明转发后保持不变
 *
 * 边界:只做透明转发,【不做】token 注入、【不做】多用户共享。
 *       只对【你本人登录的订阅】有效,在【你自己机器】上跑。纯学习/观察用途。
 *
 * 依赖:零依赖,Node 18+(或 bun)直接跑。
 */

const http = require('http')
const https = require('https')

const PORT = process.env.PROXY_PORT ? Number(process.env.PROXY_PORT) : 8787
const UPSTREAM_HOST = 'api.anthropic.com'

// 把 Bearer token 打码,只显示头尾,确认走的是 OAuth 而不泄露 token
function redactAuth(headers) {
  const a = headers.authorization || headers.Authorization
  if (!a) return '(无 Authorization —— 可能没走 OAuth)'
  const m = /^Bearer\s+(.+)$/i.exec(a)
  if (m) return `Bearer ${m[1].slice(0, 6)}…${m[1].slice(-4)}  (len=${m[1].length})`
  return a.slice(0, 14) + '…'
}

// 仅用于「展示」请求体结构 —— 注意:转发用的是原始字节,绝不用这里 parse 的结果
function summarizeBody(buf) {
  const raw = buf.toString('utf8')
  // attestation 的 cc_version / cch 藏在 system prompt 文本里(不是 HTTP 头)
  const ccv = /cc_version=([^;]+)/.exec(raw)
  const cch = /cch=([0-9a-fA-F]+)/.exec(raw)

  let p
  try {
    p = JSON.parse(raw)
  } catch {
    return { note: 'body 不是 JSON', bytes: buf.length, cc_version: ccv?.[1], cch: cch?.[1] }
  }

  const sys = p.system
  const sysPreview = Array.isArray(sys)
    ? sys.map(b => (typeof b === 'string' ? b : b?.text || '').slice(0, 70)).filter(Boolean)
    : typeof sys === 'string'
      ? [sys.slice(0, 70)]
      : []

  return {
    bytes: buf.length,
    model: p.model,
    max_tokens: p.max_tokens,
    stream: p.stream,
    betas: p.betas, // 看这里有没有 oauth-2025-04-20
    messages: Array.isArray(p.messages) ? `${p.messages.length} 条` : undefined,
    tools: Array.isArray(p.tools) ? `${p.tools.length} 个` : undefined,
    metadata: p.metadata, // user_id 里有 device_id / account_uuid / session_id
    system_blocks: Array.isArray(sys) ? sys.length : sys ? 1 : 0,
    system_preview: sysPreview, // 第一行通常是 attribution + "You are Claude Code..."
    cc_version: ccv?.[1],
    attestation_cch: cch ? cch[1] : '(没找到 —— 可能 NATIVE_CLIENT_ATTESTATION flag 关着)',
  }
}

const server = http.createServer((req, res) => {
  const chunks = []
  req.on('data', c => chunks.push(c))
  req.on('end', () => {
    const body = Buffer.concat(chunks) // ← 原始字节,转发时一字不改(保住 attestation)

    // ---- 打印请求(仅展示) ----
    console.log('\n════════════════════════ ' + new Date().toISOString())
    console.log(`${req.method} ${req.url}`)
    console.log('auth          :', redactAuth(req.headers))
    console.log('anthropic-beta:', req.headers['anthropic-beta'] || '(none)')
    console.log('anthropic-version:', req.headers['anthropic-version'] || '(none)')
    console.log('user-agent    :', req.headers['user-agent'] || '(none)')
    if (body.length) console.dir(summarizeBody(body), { depth: 5, colors: true })

    // ---- 逐字节透明转发到 api.anthropic.com ----
    const headers = { ...req.headers }
    headers.host = UPSTREAM_HOST // 关键:Host 改写成真实上游
    delete headers['content-length']
    delete headers['transfer-encoding']
    if (body.length) headers['content-length'] = Buffer.byteLength(body)

    const up = https.request(
      { host: UPSTREAM_HOST, port: 443, method: req.method, path: req.url, headers },
      upRes => {
        console.log(`  ← ${upRes.statusCode} ${upRes.headers['content-type'] || ''}`)
        res.writeHead(upRes.statusCode || 502, upRes.headers)
        upRes.pipe(res) // 流式回传:SSE 原样透传,不 buffer、不解码
      },
    )
    up.on('error', e => {
      console.error('  ✗ upstream error:', e.message)
      if (!res.headersSent) res.writeHead(502)
      res.end('proxy upstream error: ' + e.message)
    })
    if (body.length) up.write(body)
    up.end()
  })

  req.on('error', e => {
    console.error('  ✗ client error:', e.message)
  })
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`透明转发代理 → https://${UPSTREAM_HOST}`)
  console.log(`监听 http://127.0.0.1:${PORT}`)
  console.log('\n另开一个终端,这样启动 Claude Code:')
  console.log(`  ANTHROPIC_BASE_URL=http://127.0.0.1:${PORT} claude`)
  console.log('  # 注意:别设 ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN,否则会从 OAuth 掉回 API key 模式')
  console.log('\nCtrl-C 退出。\n')
})
