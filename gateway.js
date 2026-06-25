#!/usr/bin/env node
/*
 * gateway.js —— 凭证隔离网关(claude ssh 注入模式的网关化实现)
 *
 * 把 claude ssh 的「占位凭证在外、真凭证在网关注入」做成网关。两种注入模式:
 *
 *   GATEWAY_UPSTREAM_MODE=apikey (默认)  —— 产品后端:注入你自己的 ANTHROPIC_API_KEY
 *       用户拿 per-user key 访问,网关注入 x-api-key。合规的多用户产品网关。
 *
 *   GATEWAY_UPSTREAM_MODE=oauth          —— 个人多设备:注入你自己订阅的 OAuth token
 *       你在不可信/公共电脑上跑 Claude Code,本机只放【占位 token + 设备 key】,
 *       真 OAuth token 只在这台你信任的网关机器上,由网关注入 Authorization: Bearer。
 *       公共电脑上不落地真凭证。仅限【你本人、你自己的设备】,低并发,自用。
 *
 * 合规底线:
 *   - apikey 模式注入的是你正常付费的 API key。
 *   - oauth 模式注入的是【你自己的】订阅 token、给【你自己的】设备用 —— 不是分给别人。
 *     给多个不同的人用就是订阅共享,违反 ToS,且会被账号级检测命中。
 *
 * 零依赖,Node 18+。
 */

const http = require('http')
const https = require('https')
const { URL } = require('url')

const HOST = process.env.GATEWAY_HOST || '127.0.0.1' // 生产/公网暴露请放 TLS + 防火墙/VPN 后
const PORT = Number(process.env.GATEWAY_PORT || 8788)

const UPSTREAM_BASE = new URL(process.env.GATEWAY_UPSTREAM_BASE || 'https://api.anthropic.com')
const UPSTREAM_MODE = process.env.GATEWAY_UPSTREAM_MODE || 'apikey'
const transport = UPSTREAM_BASE.protocol === 'https:' ? https : http
const upstreamPort = UPSTREAM_BASE.port || (UPSTREAM_BASE.protocol === 'https:' ? 443 : 80)
const ANTHROPIC_VERSION = process.env.ANTHROPIC_VERSION || '2023-06-01'

// —— 上游凭证(网关注入,客户端永远看不到)——
const UPSTREAM_API_KEY = process.env.ANTHROPIC_API_KEY
const UPSTREAM_OAUTH = process.env.CLAUDE_GATEWAY_UPSTREAM_OAUTH
if (UPSTREAM_MODE === 'apikey' && !UPSTREAM_API_KEY) {
  console.error('✗ apikey 模式需要 ANTHROPIC_API_KEY(你自己的 API key)')
  process.exit(1)
}
if (UPSTREAM_MODE === 'oauth' && !UPSTREAM_OAUTH) {
  console.error('✗ oauth 模式需要 CLAUDE_GATEWAY_UPSTREAM_OAUTH(你自己的订阅 access token)')
  process.exit(1)
}

// —— 前置鉴权:你签发的 per-user / per-device key → { id, dailyLimit } ——
const USERS = (() => {
  if (process.env.GATEWAY_USERS) return JSON.parse(process.env.GATEWAY_USERS)
  return {
    'demo-key-alice': { id: 'alice', dailyLimit: 100 },
    'demo-key-bob': { id: 'bob', dailyLimit: 50 },
  }
})()

// —— per-user 日配额(内存版;生产用 Redis/DB)——
const usage = new Map()
function checkQuota(user) {
  const day = new Date().toISOString().slice(0, 10)
  const u = usage.get(user.id)
  if (!u || u.day !== day) { usage.set(user.id, { day, count: 1 }); return true }
  if (u.count >= user.dailyLimit) return false
  u.count++
  return true
}

const audit = e => console.log('[audit]', JSON.stringify(e))
function deny(res, code, msg, log) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ error: msg }))
  audit(log)
}

const server = http.createServer((req, res) => {
  const chunks = []
  req.on('data', c => chunks.push(c))
  req.on('end', () => {
    const body = Buffer.concat(chunks)

    // 1) 前置鉴权:用户/设备用你签发的 key,不是真凭证
    const userKey = req.headers['x-gateway-key']
    const user = userKey && USERS[userKey]
    if (!user) {
      return deny(res, 401, 'invalid gateway key', { ts: Date.now(), ok: false, reason: 'auth', path: req.url })
    }
    // 2) 配额
    if (!checkQuota(user)) {
      return deny(res, 429, 'daily quota exceeded', { ts: Date.now(), ok: false, reason: 'quota', user: user.id })
    }
    // 3) 模型(仅审计)
    let model
    try { model = JSON.parse(body.toString('utf8')).model } catch {}

    // 4) 构造上游 header —— 注入真凭证,剥掉客户端凭证企图
    let headers
    if (UPSTREAM_MODE === 'oauth') {
      // 透明转发:保留客户端(真 Claude Code)拼好的所有头(betas/版本/UA/attestation 在 body),
      // 只换 Host + Authorization,剥掉设备 key。
      headers = { ...req.headers }
      headers.host = UPSTREAM_BASE.host
      headers['authorization'] = `Bearer ${UPSTREAM_OAUTH}` // ← 注入真订阅 token
      delete headers['x-gateway-key']
      delete headers['x-api-key']
      delete headers['content-length']
      if (body.length) headers['content-length'] = Buffer.byteLength(body)
    } else {
      // apikey 模式:精简头 + 注入 x-api-key
      headers = {
        host: UPSTREAM_BASE.host,
        'content-type': req.headers['content-type'] || 'application/json',
        'anthropic-version': req.headers['anthropic-version'] || ANTHROPIC_VERSION,
        'x-api-key': UPSTREAM_API_KEY, // ← 注入真 API key
      }
      if (req.headers['anthropic-beta']) headers['anthropic-beta'] = req.headers['anthropic-beta']
      if (req.headers['accept']) headers['accept'] = req.headers['accept']
      if (body.length) headers['content-length'] = Buffer.byteLength(body)
    }

    // 5) 逐字节透明转发到硬编码上游(测试时可由 GATEWAY_UPSTREAM_BASE 指向 mock)
    const path = req.url.startsWith('/v1/') ? req.url : '/v1/messages'
    const up = transport.request(
      { host: UPSTREAM_BASE.hostname, port: upstreamPort, method: req.method, path, headers },
      upRes => {
        audit({ ts: Date.now(), ok: true, user: user.id, model, status: upRes.statusCode, mode: UPSTREAM_MODE })
        res.writeHead(upRes.statusCode || 502, upRes.headers)
        upRes.pipe(res) // SSE 流式回传
      },
    )
    up.on('error', e => {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'upstream error: ' + e.message }))
      audit({ ts: Date.now(), ok: false, reason: 'upstream', user: user.id, err: e.message })
    })
    if (body.length) up.write(body)
    up.end()
  })
  req.on('error', () => {})
})

server.listen(PORT, HOST, () => {
  console.log(`凭证隔离网关 [${UPSTREAM_MODE}] → ${UPSTREAM_BASE.origin}`)
  console.log(`监听 http://${HOST}:${PORT}`)
  if (UPSTREAM_MODE === 'oauth') console.log(`注入: 订阅 OAuth token (len=${UPSTREAM_OAUTH.length})`)
  else console.log(`注入: ANTHROPIC_API_KEY (len=${UPSTREAM_API_KEY.length})`)
  console.log(`设备/用户 key: ${Object.values(USERS).map(u => `${u.id}(${u.dailyLimit}/day)`).join(', ')}`)
})
