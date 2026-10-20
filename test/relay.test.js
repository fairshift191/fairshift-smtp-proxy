import assert from 'node:assert/strict'
import net from 'node:net'
import { after, before, test } from 'node:test'

process.env.NODE_ENV = 'test'
process.env.SMTP_PROXY_SECRET = 'local-test-secret'
const { app } = await import('../index.js')
let http, smtp, origin, smtpPort
const delivered = []

before(async () => {
  smtp = net.createServer(socket => {
    let buffer = '', data = false, message = [], recipients = []
    socket.write('220 local.test ESMTP\r\n')
    socket.on('data', bytes => {
      buffer += bytes.toString()
      let end
      while ((end = buffer.indexOf('\r\n')) !== -1) {
        const line = buffer.slice(0, end)
        buffer = buffer.slice(end + 2)
        if (data) {
          if (line === '.') {
            delivered.push({ recipients, raw: message.join('\r\n') })
            data = false
            socket.write('250 accepted locally\r\n')
          } else message.push(line.startsWith('..') ? line.slice(1) : line)
        } else if (/^EHLO\b/i.test(line)) socket.write('250-local.test\r\n250 AUTH PLAIN\r\n')
        else if (/^AUTH PLAIN\b/i.test(line)) socket.write('235 authenticated locally\r\n')
        else if (/^MAIL FROM:/i.test(line)) { recipients = []; message = []; socket.write('250 sender accepted\r\n') }
        else if (/^RCPT TO:/i.test(line)) {
          const recipient = line.match(/<([^>]+)>/)?.[1]
          if (recipient === 'reject@example.test') socket.write('550 recipient rejected\r\n')
          else { recipients.push(recipient); socket.write('250 recipient accepted\r\n') }
        } else if (/^DATA$/i.test(line)) { data = true; socket.write('354 end with dot\r\n') }
        else if (/^QUIT$/i.test(line)) { socket.end('221 bye\r\n') }
        else socket.write('250 ok\r\n')
      }
    })
  })
  await new Promise(resolve => smtp.listen(0, '127.0.0.1', resolve))
  smtpPort = smtp.address().port
  http = await new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)) })
  origin = `http://127.0.0.1:${http.address().port}`
})

after(async () => {
  http?.closeAllConnections()
  await Promise.all([http, smtp].filter(Boolean).map(server => new Promise(resolve => server.close(resolve))))
})

const payload = () => ({
  smtp_host: '127.0.0.1', smtp_port: smtpPort,
  smtp_user: 'sender@example.test', smtp_pass: 'local-test-only',
  from: 'Sender <sender@example.test>', to: 'buyer@example.test',
  subject: 'Local relay test', text: 'Synthetic test only',
})
const send = body => fetch(`${origin}/send`, { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': 'local-test-secret' }, body: JSON.stringify(body) })

test('advertises the exact delivery receipt contract without contacting SMTP', async () => {
  const before = delivered.length
  assert.deepEqual(await (await fetch(`${origin}/health`)).json(), { ok: true, delivery_receipt_version: 2 })
  assert.equal(delivered.length, before)
})

test('verifies authentication with both old and new response fields without sending', async () => {
  const before = delivered.length
  const response = await fetch(`${origin}/verify`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': 'local-test-secret' }, body: JSON.stringify(payload()) })
  assert.deepEqual(await response.json(), { ok: true, verified: true })
  assert.equal(delivered.length, before)
})

test('passes PDF, CC, reply headers and stable message id, returning real recipient receipts', async () => {
  const pdf = Buffer.from('%PDF-1.7\nSynthetic local fixture\n%%EOF')
  const response = await send({ ...payload(), cc: ['copy@example.test', 'reject@example.test'],
    headers: { 'Message-ID': '<fixed@sender.test>', 'X-Fairshift-Send-Id': 'local-send-id',
      'In-Reply-To': '<original@buyer.test>', References: '<older@buyer.test> <original@buyer.test>' },
    attachments: [{ filename: 'offer.pdf', contentType: 'application/pdf', encoding: 'base64', content: pdf.toString('base64') }],
  })
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true, message_id: '<fixed@sender.test>',
    accepted: ['buyer@example.test', 'copy@example.test'], rejected: ['reject@example.test'] })
  const message = delivered.at(-1)
  assert.deepEqual(message.recipients, ['buyer@example.test', 'copy@example.test'])
  assert.match(message.raw, /^Message-ID: <fixed@sender\.test>$/im)
  assert.match(message.raw, /^X-Fairshift-Send-ID: local-send-id$/im)
  assert.match(message.raw, /^In-Reply-To: <original@buyer\.test>$/im)
  assert.match(message.raw, /^References: <older@buyer\.test> <original@buyer\.test>$/im)
  assert.match(message.raw, /^Cc: copy@example\.test, reject@example\.test$/im)
  assert.match(message.raw, /Content-Type: application\/pdf; name=offer\.pdf/i)
  assert.ok(message.raw.includes(pdf.toString('base64')))
})

test('preserves legacy top-level message ids and both stored attachment encodings', async () => {
  const pdf = Buffer.from('%PDF-1.7\nLegacy fixture\n%%EOF')
  const response = await send({ ...payload(), message_id: '<legacy@sender.test>', attachments: [
    { filename: 'implicit-base64.pdf', content: pdf.toString('base64') },
    { filename: 'buffer.pdf', content: pdf.toJSON() },
  ] })
  assert.equal((await response.json()).message_id, '<legacy@sender.test>')
  const message = delivered.at(-1)
  assert.match(message.raw, /filename=implicit-base64\.pdf/i)
  assert.match(message.raw, /filename=buffer\.pdf/i)
  assert.equal(message.raw.split(pdf.toString('base64')).length - 1, 2)
})

test('accepts a ten MiB PDF after base64 encoding', async () => {
  const pdf = Buffer.alloc(10 * 1024 * 1024, 65)
  pdf.write('%PDF-1.7\n')
  const response = await send({ ...payload(), headers: { 'Message-ID': '<large@sender.test>' },
    attachments: [{ filename: 'large.pdf', content: pdf.toString('base64'), encoding: 'base64' }],
  })
  assert.equal(response.status, 200)
  assert.equal((await response.json()).message_id, '<large@sender.test>')
  assert.match(delivered.at(-1).raw, /filename=large\.pdf/i)
})

test('rejects a wrong shared secret before any SMTP delivery', async () => {
  const before = delivered.length
  const response = await fetch(`${origin}/send`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': 'wrong' }, body: JSON.stringify(payload()) })
  assert.equal(response.status, 401)
  assert.equal(delivered.length, before)
})
