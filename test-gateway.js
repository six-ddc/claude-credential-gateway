#!/usr/bin/env node
/*
 * test-gateway.js —— 验证 gateway.js 的 oauth 注入模式(订阅网关模式)的「管子」
 *
 * 用假凭证、mock 上游,验证:
 *   1. 网关把客户端的【占位 token】换成了【真订阅 token】(注入成功)
 *   2. 占位 token 没有泄露到上游
 *   3. 设备 key(x-gateway-key)没有泄露到上游
 *   4. 请求 body 逐字节不变(attestation 安全的前提)
 *   5. SSE 响应流式透传回客户端
 *   6. 无效设备 key → 401
 *
 * 不涉及任何真实凭证、不打真实 API。
 */

const http = require('http')
const { spawn } = require('child_process')
const net = require('net')

const PLACEHOLDER = 'placeholder-token-aaaaaaaa' // 公共电脑上放的假占位
const REAL_OAUTH = 'real-subscription-token-FAKE-bbbbbbbb' // 网关里的(测试用假值)
const DEVICE_KEY = 'device-laptop-1'
const MOCK_PORT = 9911
const GW_PORT = 9912

const REQ_BODY = JSON.stringify({
  model: 'claude-sonnet-4-6',
  max_tokens: 64,
  messages: [{ role: 'user', content: 'ping' }],
})

let captured = null

// —— mock 上游(冒充 api.anthropic.com)——
const mock = http.createServer((req, res) => {
  const chunks = []
  req.on('data', c => chunks.push(c))
  req.on('end', () => {
    captured = {
      authorization: req.headers['authorization'],
      xApiKey: req.headers['x-api-key'],
      xGatewayKey: req.headers['x-gateway-key'],
      anthropicBeta: req.headers['anthropic-beta'],
      host: req.headers['host'],
      body: Buffer.concat(chunks).toString('utf8'),
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write('event: message_start\ndata: {"type":"message_start"}\n\n')
    res.write('event: content_block_delta\ndata: {"delta":{"text":"pong"}}\n\n')
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n')
  })
})

function waitPort(port, cb, tries = 0) {
  const s = net.connect(port, '127.0.0.1')
  s.on('connect', () => { s.destroy(); cb() })
  s.on('error', () => {
    s.destroy()
    if (tries > 50) throw new Error('gateway 未就绪')
    setTimeout(() => waitPort(port, cb, tries + 1), 100)
  })
}

function call(headers, cb) {
  const req = http.request(
    { host: '127.0.0.1', port: GW_PORT, path: '/v1/messages', method: 'POST', headers },
    res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => cb(res.statusCode, Buffer.concat(chunks).toString('utf8')))
    },
  )
  req.end(REQ_BODY)
}

const results = []
const check = (name, ok, detail) => results.push({ name, ok, detail })

mock.listen(MOCK_PORT, '127.0.0.1', () => {
  const gw = spawn('node', [__dirname + '/gateway.js'], {
    env: {
      ...process.env,
      GATEWAY_PORT: String(GW_PORT),
      GATEWAY_HOST: '127.0.0.1',
      GATEWAY_UPSTREAM_MODE: 'oauth',
      GATEWAY_UPSTREAM_BASE: `http://127.0.0.1:${MOCK_PORT}`,
      CLAUDE_GATEWAY_UPSTREAM_OAUTH: REAL_OAUTH,
      GATEWAY_USERS: JSON.stringify({ [DEVICE_KEY]: { id: 'laptop-1', dailyLimit: 100 } }),
    },
    stdio: ['ignore', 'inherit', 'inherit'],
  })

  const done = () => {
    gw.kill()
    mock.close()
    console.log('\n──────── 测试结果 ────────')
    let allOk = true
    for (const r of results) {
      console.log(`${r.ok ? '✓' : '✗'} ${r.name}${r.detail ? '  — ' + r.detail : ''}`)
      if (!r.ok) allOk = false
    }
    console.log(allOk ? '\n全部通过 ✅' : '\n有失败 ❌')
    process.exit(allOk ? 0 : 1)
  }

  waitPort(GW_PORT, () => {
    // 用例 A:带占位 token + 设备 key 的正常请求
    call(
      {
        'content-type': 'application/json',
        'x-gateway-key': DEVICE_KEY,
        authorization: `Bearer ${PLACEHOLDER}`,
        'anthropic-beta': 'oauth-2025-04-20',
      },
      (status, respBody) => {
        check('上游收到的是真订阅 token(注入成功)', captured?.authorization === `Bearer ${REAL_OAUTH}`, captured?.authorization)
        check('占位 token 未泄露到上游', !!captured && !captured.authorization.includes(PLACEHOLDER))
        check('设备 key 未泄露到上游', !captured?.xGatewayKey)
        check('body 逐字节不变', captured?.body === REQ_BODY)
        check('anthropic-beta 透传', captured?.anthropicBeta === 'oauth-2025-04-20')
        check('Host 改写为上游', captured?.host === `127.0.0.1:${MOCK_PORT}`)
        check('SSE 响应流式回传', status === 200 && respBody.includes('pong') && respBody.includes('message_stop'))

        // 用例 B:无效设备 key → 401
        call(
          { 'content-type': 'application/json', 'x-gateway-key': 'wrong', authorization: `Bearer ${PLACEHOLDER}` },
          status2 => {
            check('无效设备 key 被拒(401)', status2 === 401, 'status=' + status2)
            done()
          },
        )
      },
    )
  })
})
