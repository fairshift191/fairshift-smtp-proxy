import express from 'express'
import nodemailer from 'nodemailer'

const app  = express()
const PORT = process.env.PORT || 3000
const SECRET = process.env.SMTP_PROXY_SECRET

app.use(express.json())

// ─── Auth ─────────────────────────────────────────────────────────────────────
function requireSecret(req, res, next) {
  if (!SECRET) return next() // dev: no secret = open
  if (req.headers['x-proxy-secret'] !== SECRET) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  next()
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true }))

// ─── POST /verify — test SMTP credentials ────────────────────────────────────
app.post('/verify', requireSecret, async (req, res) => {
  const { smtp_host, smtp_port, smtp_user, smtp_pass } = req.body
  if (!smtp_host || !smtp_port || !smtp_user || !smtp_pass) {
    return res.status(400).json({ verified: false, error: 'smtp_host, smtp_port, smtp_user, smtp_pass required' })
  }

  const port = parseInt(smtp_port)
  try {
    const transporter = nodemailer.createTransport({
      host: smtp_host,
      port,
      secure: port === 465,
      auth: { user: smtp_user, pass: smtp_pass },
      connectionTimeout: 15000,
      greetingTimeout:   10000,
      socketTimeout:     15000,
      tls: { rejectUnauthorized: false },
    })
    await transporter.verify()
    console.log(`[proxy] verified ${smtp_user}@${smtp_host}:${port}`)
    res.json({ verified: true })
  } catch (err) {
    console.warn(`[proxy] verify failed ${smtp_host}:${port} —`, err.message)
    res.json({ verified: false, error: err.message })
  }
})

// ─── POST /send — send an email through a tenant's mailbox ───────────────────
app.post('/send', requireSecret, async (req, res) => {
  const { smtp_host, smtp_port, smtp_user, smtp_pass, from, to, subject, text, html, reply_to } = req.body
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
    await transporter.sendMail({ from, to, subject, text, html, replyTo: reply_to })
    console.log(`[proxy] sent from ${from} → ${to}`)
    res.json({ ok: true })
  } catch (err) {
    console.warn(`[proxy] send failed from ${from} → ${to}:`, err.message)
    res.json({ ok: false, error: err.message })
  }
})

app.listen(PORT, () => console.log(`fairshift-smtp-proxy listening on ${PORT}`))
