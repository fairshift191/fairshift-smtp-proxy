import express from 'express'
import nodemailer from 'nodemailer'

export const app  = express()
const PORT = process.env.PORT || 3000
const SECRET = process.env.SMTP_PROXY_SECRET

// Gmail accepts 25MB of attachments, and base64 inflates by about a third, so
// the JSON carrying them has to be allowed past Express's 100kb default. That
// default is why every report Fairshift tried to attach came back 413 — a
// limit nobody chose, on our own proxy.
app.use(express.json({ limit: '40mb' }))

// ─── Auth ─────────────────────────────────────────────────────────────────────
function requireSecret(req, res, next) {
  if (!SECRET) return next() // dev: no secret = open
  if (req.headers['x-proxy-secret'] !== SECRET) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  next()
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, delivery_receipt_version: 2 }))

// ─── POST /verify — test SMTP credentials ────────────────────────────────────
app.post('/verify', requireSecret, async (req, res) => {
  const { smtp_host, smtp_port, smtp_user, smtp_pass } = req.body
  if (!smtp_host || !smtp_user || !smtp_pass) {
    return res.status(400).json({ ok: false, verified: false, error: 'smtp_host, smtp_user, smtp_pass required' })
  }
  const port = parseInt(smtp_port || 587)
  try {
    const transporter = nodemailer.createTransport({
      host: smtp_host,
      port,
      secure: port === 465,
      auth: { user: smtp_user, pass: smtp_pass },
      connectionTimeout: 15000,
      socketTimeout:     15000,
      tls: { rejectUnauthorized: false },
    })
    await transporter.verify()
    res.json({ ok: true, verified: true })
  } catch (err) {
    res.json({ ok: false, verified: false, error: err.message })
  }
})

/**
 * Attachments arrive as base64 in JSON, because that is the only shape that
 * survives the trip. A Node Buffer JSON-stringifies to {type:'Buffer',data:[…]},
 * which nodemailer does not understand, so the caller encodes and this decodes.
 */
function normaliseAttachments(attachments) {
  if (!Array.isArray(attachments) || !attachments.length) return undefined
  return attachments.map((file) => ({
    filename: file.filename,
    content: file?.content?.type === 'Buffer' && Array.isArray(file.content.data)
      ? Buffer.from(file.content.data) : file.content,
    ...(file.encoding ? { encoding: file.encoding } : { encoding: 'base64' }),
    ...(file.contentType ? { contentType: file.contentType } : {}),
    ...(file.cid ? { cid: file.cid } : {}),
  }))
}

// ─── POST /send ───────────────────────────────────────────────────────────────
app.post('/send', requireSecret, async (req, res) => {
  const {
    smtp_host, smtp_port, smtp_user, smtp_pass,
    from, to, subject, text, html, reply_to,
    // Everything below used to be dropped on the floor. The handler read a
    // fixed list of fields and passed only those to nodemailer, so a caller
    // could send attachments, a cc list, or threading headers, get {ok:true},
    // and never learn they had not been delivered. That silently cost every
    // attached report, every reply-all, In-Reply-To on every reply (so nothing
    // threaded), and the RFC 8058 List-Unsubscribe headers on bulk mail.
    cc, bcc, headers, attachments, message_id,
  } = req.body
  if (!smtp_host || !smtp_user || !smtp_pass || !from || !to || !subject) {
    return res.status(400).json({ ok: false, error: 'smtp_host, smtp_user, smtp_pass, from, to, subject required' })
  }

  const port = parseInt(smtp_port || 587)
  try {
    const transporter = nodemailer.createTransport({
      host: smtp_host,
      port,
      secure: port === 465,
      auth: { user: smtp_user, pass: smtp_pass },
      connectionTimeout: 15000,
      socketTimeout:     15000,
      tls: { rejectUnauthorized: false },
    })
    const info = await transporter.sendMail({
      from, to, subject, text, html,
      replyTo: reply_to,
      ...(cc ? { cc } : {}),
      ...(bcc ? { bcc } : {}),
      ...(headers ? { headers } : {}),
      ...((message_id || headers?.['Message-ID'] || headers?.['Message-Id'] || headers?.['message-id'])
        ? { messageId: message_id || headers?.['Message-ID'] || headers?.['Message-Id'] || headers?.['message-id'] } : {}),
      attachments: normaliseAttachments(attachments),
    })
    const files = Array.isArray(attachments) ? attachments.length : 0
    console.log(`[proxy] sent from ${from} → ${to}${files ? ` (${files} attachment${files === 1 ? '' : 's'})` : ''} id=${info.messageId}`)
    // The caller stores message_id to match inbound replies back to the send
    // it answers. Returning only {ok:true} meant every send was stored with a
    // null id and no reply could ever be linked to one.
    res.json({
      ok: true,
      message_id: info.messageId || null,
      accepted: info.accepted || [],
      rejected: info.rejected || [],
    })
  } catch (err) {
    console.warn(`[proxy] send failed from ${from} → ${to}:`, err.message)
    res.json({ ok: false, error: err.message })
  }
})

if (process.env.NODE_ENV !== 'test') app.listen(PORT, () => console.log(`fairshift-smtp-proxy listening on ${PORT}`))
