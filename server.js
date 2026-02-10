const express = require('express');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3002;

// Data directory: /var/data on Render (persistent disk), local ./data otherwise
const dataDir = fs.existsSync('/var/data') ? '/var/data' : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Database setup
const db = new Database(path.join(dataDir, 'integration.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    id TEXT PRIMARY KEY DEFAULT 'main',
    lava_api_key TEXT DEFAULT '',
    gc_account TEXT DEFAULT '',
    gc_secret TEXT DEFAULT '',
    poll_interval INTEGER DEFAULT 120,
    last_sync_at TEXT DEFAULT '',
    is_active INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS mappings (
    id TEXT PRIMARY KEY,
    lava_product_name TEXT NOT NULL,
    lava_offer_id TEXT DEFAULT '',
    gc_action TEXT DEFAULT 'both',
    gc_group_name TEXT DEFAULT '',
    gc_offer_code TEXT DEFAULT '',
    gc_product_title TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    condition_type TEXT NOT NULL DEFAULT 'product_equals',
    condition_value TEXT NOT NULL DEFAULT '',
    actions TEXT NOT NULL DEFAULT '[]',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS action_log (
    id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    email TEXT DEFAULT '',
    details TEXT DEFAULT '',
    status TEXT DEFAULT 'success',
    error_message TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sync_log (
    id TEXT PRIMARY KEY,
    lava_invoice_id TEXT UNIQUE,
    buyer_email TEXT,
    product_name TEXT,
    amount REAL,
    currency TEXT,
    gc_user_id TEXT DEFAULT '',
    gc_deal_id TEXT DEFAULT '',
    gc_status TEXT,
    gc_error TEXT DEFAULT '',
    processed_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Add webhook_secret column if missing
try { db.exec("ALTER TABLE settings ADD COLUMN webhook_secret TEXT DEFAULT ''"); } catch (e) {}

// Ensure default settings row with webhook secret
const existingSettings = db.prepare('SELECT id FROM settings WHERE id = ?').get('main');
if (!existingSettings) {
  db.prepare('INSERT INTO settings (id, webhook_secret) VALUES (?, ?)').run('main', uuidv4());
} else {
  const s = db.prepare('SELECT webhook_secret FROM settings WHERE id = ?').get('main');
  if (!s.webhook_secret) {
    db.prepare("UPDATE settings SET webhook_secret = ? WHERE id = 'main'").run(uuidv4());
  }
}

// Seed settings from environment variables (survives Render redeploys)
{
  const envLava = process.env.LAVA_API_KEY || 'voiK0UAigPWtG0v1r8hqe8ABmKElGeAOGt3950mcmFbT80yaIRhOwJGuI84aMVfl';
  const envGcAccount = process.env.GC_ACCOUNT || 'systemicaa';
  const envGcSecret = process.env.GC_SECRET || 'UPPi1hmDBl5ttHXppjHsUjO5l9yxqk2dIuLyko9xraqqnqPGXaNC91sAoSBsdtqfG65p5O37rycYDnC6Jh2dFavNImvx9NTRRXFZsBZWNtrIWZrwkqSxEu3KitGYPQqV';
  const envWebhookSecret = process.env.WEBHOOK_SECRET || '4a8a88f5-05a8-4af1-a7be-c27ea907c0dc';
  const envPollInterval = process.env.POLL_INTERVAL ? parseInt(process.env.POLL_INTERVAL) : 120;
  const envIsActive = process.env.SYNC_ACTIVE !== '0' ? 1 : null;
  const current = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');
  if (envLava && !current.lava_api_key) db.prepare("UPDATE settings SET lava_api_key = ? WHERE id = 'main'").run(envLava);
  if (envGcAccount && !current.gc_account) db.prepare("UPDATE settings SET gc_account = ? WHERE id = 'main'").run(envGcAccount);
  if (envGcSecret && !current.gc_secret) db.prepare("UPDATE settings SET gc_secret = ? WHERE id = 'main'").run(envGcSecret);
  if (envWebhookSecret && !current.webhook_secret) db.prepare("UPDATE settings SET webhook_secret = ? WHERE id = 'main'").run(envWebhookSecret);
  if (envPollInterval !== null) db.prepare("UPDATE settings SET poll_interval = ? WHERE id = 'main'").run(envPollInterval);
  if (envIsActive !== null) db.prepare("UPDATE settings SET is_active = ? WHERE id = 'main'").run(envIsActive);
  if (envLava || envGcAccount || envGcSecret) console.log('Settings seeded from environment variables');
}

app.use(express.json());

// ─── Basic Auth ───
const AUTH_USER = process.env.AUTH_USER || 'prov02';
const AUTH_PASS = process.env.AUTH_PASS || 'PetrVideo20021604';

function basicAuth(req, res, next) {
  // Skip auth for webhook (external service calls it)
  if (req.path === '/api/webhook/lava') return next();
  // Skip auth for payment pages (public)
  if (req.path.startsWith('/pay/')) return next();
  // Skip auth for invoice creation (called from payment page)
  if (req.path === '/api/create-invoice') return next();

  const header = req.headers.authorization || '';
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString();
    const [user, pass] = decoded.split(':');
    if (user === AUTH_USER && pass === AUTH_PASS) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="LavaTop-GetCourse"');
  res.status(401).send('Требуется авторизация');
}

app.use(basicAuth);
app.use(express.static(__dirname));

// ─── LavaTop Webhook ───

app.post('/api/webhook/lava', async (req, res) => {
  // Verify API key
  const incomingKey = req.headers['x-api-key'] || '';
  const settings = db.prepare('SELECT webhook_secret FROM settings WHERE id = ?').get('main');
  if (settings?.webhook_secret && incomingKey !== settings.webhook_secret) {
    console.log('Webhook rejected: invalid API key');
    return res.status(401).json({ error: 'Invalid API key' });
  }

  // Respond 200 immediately so LavaTop doesn't retry
  res.json({ ok: true });

  const payload = req.body;
  console.log('Webhook received:', JSON.stringify(payload).slice(0, 500));

  try {
    // LavaTop PurchaseWebhookLog format:
    // { eventType, contractId, parentContractId, buyer: { email }, product: { id, title }, amount, currency, status, timestamp, clientUtm, errorMessage }
    const eventType = payload.eventType || payload.type || payload.event || '';

    // Only process successful payments
    if (eventType && !eventType.toLowerCase().includes('success')) {
      console.log('Webhook skipped: event type', eventType);
      return;
    }

    // Extract fields from PurchaseWebhookLog
    const buyerEmail = payload.buyer?.email || '';
    const productName = payload.product?.title || payload.product?.name || '';
    const productId = payload.product?.id || '';
    const offerId = productId;
    const invoiceId = payload.contractId || payload.id || uuidv4();
    const amount = payload.amount || 0;
    const currency = payload.currency || '';

    if (!buyerEmail) {
      console.log('Webhook skipped: no buyer email');
      logAction('webhook_received', '', { invoiceId, productName, error: 'no email' }, 'error', 'Email покупателя отсутствует');
      return;
    }

    // Check if already processed
    const existing = db.prepare('SELECT id FROM sync_log WHERE lava_invoice_id = ?').get(invoiceId);
    if (existing) {
      console.log('Webhook skipped: already processed', invoiceId);
      return;
    }

    logAction('webhook_received', buyerEmail, { invoiceId, productName, amount, currency });

    // Find matching rule
    const settings = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');
    if (!settings?.gc_secret || !settings?.gc_account) {
      console.log('Webhook skipped: GC not configured');
      db.prepare(`INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
        VALUES (?, ?, ?, ?, ?, ?, 'error', ?, ?)`)
        .run(uuidv4(), invoiceId, buyerEmail, productName, amount, currency, 'GetCourse не настроен', new Date().toISOString());
      return;
    }

    const rules = db.prepare('SELECT * FROM rules WHERE is_active = 1').all().map(r => ({ ...r, actions: JSON.parse(r.actions || '[]') }));
    const mappings = db.prepare('SELECT * FROM mappings WHERE is_active = 1').all();

    // Check user existence in GC if needed
    let gcUserStatus = null;
    const needsGcCheck = rules.some(r => r.condition_type === 'user_exists_gc' || r.condition_type === 'user_not_exists_gc');
    if (needsGcCheck) {
      try {
        const checkRes = await gcApiCall(settings, 'users', { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } });
        gcUserStatus = checkRes.success ? (checkRes.result?.user_status || 'updated') : null;
      } catch (e) { gcUserStatus = null; }
    }

    const matchedRule = rules.find(r => {
      const val = (r.condition_value || '').toLowerCase();
      if (r.condition_type === 'product_equals') return productName.toLowerCase() === val;
      if (r.condition_type === 'product_contains') return productName.toLowerCase().includes(val);
      if (r.condition_type === 'email_contains') return buyerEmail.toLowerCase().includes(val);
      if (r.condition_type === 'email_equals') return buyerEmail.toLowerCase() === val;
      if (r.condition_type === 'amount_gte') return parseFloat(amount) >= parseFloat(r.condition_value);
      if (r.condition_type === 'amount_lte') return parseFloat(amount) <= parseFloat(r.condition_value);
      if (r.condition_type === 'user_exists_gc') return gcUserStatus === 'updated';
      if (r.condition_type === 'user_not_exists_gc') return gcUserStatus === 'added';
      return false;
    });

    const mapping = !matchedRule ? mappings.find(m =>
      (m.lava_product_name && productName.toLowerCase().includes(m.lava_product_name.toLowerCase())) ||
      (m.lava_offer_id && (m.lava_offer_id === offerId || m.lava_offer_id === invoiceId))
    ) : null;

    let gcUserId = '';
    let gcDealId = '';
    let gcError = '';
    let gcStatus = 'success';

    if (!matchedRule && !mapping) {
      // No rule/mapping — just log the payment
      db.prepare(`INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
        VALUES (?, ?, ?, ?, ?, ?, 'error', ?, ?)`)
        .run(uuidv4(), invoiceId, buyerEmail, productName, amount, currency, 'Правило/маппинг не найдены', new Date().toISOString());
      return;
    }

    try {
      if (matchedRule) {
        const result = await executeActions(matchedRule.actions, settings, buyerEmail, amount, productName, matchedRule.name, 'webhook');
        gcUserId = result.gcUserId;
        gcDealId = result.gcDealId;
      } else {
        if (mapping.gc_action === 'group' || mapping.gc_action === 'both') {
          const userParams = { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } };
          if (mapping.gc_group_name) userParams.user.group_name = [mapping.gc_group_name];
          const userRes = await gcApiCall(settings, 'users', userParams);
          if (userRes.success) {
            gcUserId = String(userRes.result?.user_id || '');
            logAction('added_to_group', buyerEmail, { user_id: gcUserId, group: mapping.gc_group_name, product: productName, source: 'webhook' });
          } else throw new Error(userRes.error_message || 'Ошибка создания пользователя');
        }
        if (mapping.gc_action === 'deal' || mapping.gc_action === 'both') {
          const dealParams = { user: { email: buyerEmail }, deal: { deal_cost: amount, deal_is_paid: 'yes' }, system: { refresh_if_exists: 1 } };
          if (mapping.gc_offer_code) dealParams.deal.offer_code = mapping.gc_offer_code;
          if (mapping.gc_product_title) dealParams.deal.product_title = mapping.gc_product_title;
          const dealRes = await gcApiCall(settings, 'deals', dealParams);
          if (dealRes.success) {
            gcDealId = String(dealRes.result?.deal_id || '');
            logAction('product_granted', buyerEmail, { deal_id: gcDealId, offer_code: mapping.gc_offer_code, product: productName, source: 'webhook' });
          } else throw new Error(dealRes.error_message || 'Ошибка создания заказа');
        }
      }
    } catch (e) {
      gcStatus = 'error';
      gcError = e.message;
      logAction('gc_error', buyerEmail, { product: productName, source: 'webhook' }, 'error', e.message);
    }

    db.prepare(`INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_user_id, gc_deal_id, gc_status, gc_error, processed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(uuidv4(), invoiceId, buyerEmail, productName, amount, currency, gcUserId, gcDealId, gcStatus, gcError, new Date().toISOString());

    console.log(`Webhook processed: ${buyerEmail} / ${productName} → ${gcStatus}`);
  } catch (e) {
    console.error('Webhook processing error:', e.message);
  }
});

// ─── Action Log Helper ───
function logAction(action_type, email, details, status = 'success', error_message = '') {
  db.prepare(`INSERT INTO action_log (id, action_type, email, details, status, error_message) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(uuidv4(), action_type, email || '', typeof details === 'string' ? details : JSON.stringify(details), status, error_message);
}

// ─── Action Log API ───
app.get('/api/action-log', (req, res) => {
  const { page = 1, limit = 50, action_type, email } = req.query;
  let where = [];
  let params = [];
  if (action_type) { where.push('action_type = ?'); params.push(action_type); }
  if (email) { where.push('email LIKE ?'); params.push(`%${email}%`); }
  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const total = db.prepare(`SELECT COUNT(*) as cnt FROM action_log ${whereClause}`).get(...params).cnt;
  const rows = db.prepare(`SELECT * FROM action_log ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);
  res.json({ items: rows, total, page: parseInt(page), limit: parseInt(limit) });
});

app.delete('/api/action-log/clear', (req, res) => {
  db.prepare('DELETE FROM action_log').run();
  res.json({ success: true });
});

// ─── Settings ───

app.get('/api/settings', (req, res) => {
  const row = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');
  // Mask API keys for security
  res.json({
    ...row,
    lava_api_key_masked: row.lava_api_key ? '••••' + row.lava_api_key.slice(-4) : '',
    gc_secret_masked: row.gc_secret ? '••••' + row.gc_secret.slice(-4) : '',
    lava_api_key: row.lava_api_key,
    gc_secret: row.gc_secret
  });
});

app.post('/api/settings', (req, res) => {
  const { lava_api_key, gc_account, gc_secret, poll_interval, is_active } = req.body;
  db.prepare(`
    UPDATE settings SET
      lava_api_key = COALESCE(?, lava_api_key),
      gc_account = COALESCE(?, gc_account),
      gc_secret = COALESCE(?, gc_secret),
      poll_interval = COALESCE(?, poll_interval),
      is_active = COALESCE(?, is_active)
    WHERE id = 'main'
  `).run(lava_api_key, gc_account, gc_secret, poll_interval, is_active);

  // Restart polling with new interval
  restartPolling();
  res.json({ success: true });
});

app.post('/api/settings/test', async (req, res) => {
  const settings = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');
  const results = { lava: null, gc: null };

  // Test LavaTop
  try {
    if (!settings.lava_api_key) throw new Error('API ключ LavaTop не указан');
    const lavaRes = await fetch('https://gate.lava.top/api/v2/invoices?page=1&size=1', {
      headers: { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' }
    });
    if (lavaRes.ok) {
      results.lava = { success: true, message: 'Подключение к LavaTop успешно' };
    } else {
      const errText = await lavaRes.text();
      results.lava = { success: false, message: `Ошибка LavaTop: ${lavaRes.status} ${errText}` };
    }
  } catch (e) {
    results.lava = { success: false, message: `Ошибка LavaTop: ${e.message}` };
  }

  // Test GetCourse — call /pl/api/users with empty params to validate the key
  try {
    if (!settings.gc_account || !settings.gc_secret) throw new Error('Аккаунт или секрет GetCourse не указаны');
    const testParams = Buffer.from(JSON.stringify({ user: { email: 'test@test.test' }, system: { refresh_if_exists: 1 } })).toString('base64');
    const body = new URLSearchParams({ action: 'add', key: settings.gc_secret, params: testParams });
    const gcRes = await fetch(`https://${settings.gc_account}.getcourse.ru/pl/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    if (gcRes.ok) {
      const data = await gcRes.json();
      if (data.success) {
        results.gc = { success: true, message: 'Подключение к GetCourse успешно' };
      } else if (data.error_message && data.error_message.includes('key')) {
        results.gc = { success: false, message: `Неверный ключ GetCourse: ${data.error_message}` };
      } else {
        // API responded — key is valid, even if there's a validation error
        results.gc = { success: true, message: 'Подключение к GetCourse успешно' };
      }
    } else {
      results.gc = { success: false, message: `Ошибка GetCourse: HTTP ${gcRes.status}` };
    }
  } catch (e) {
    results.gc = { success: false, message: `Ошибка GetCourse: ${e.message}` };
  }

  res.json(results);
});

// ─── Mappings ───

app.get('/api/mappings', (req, res) => {
  const rows = db.prepare('SELECT * FROM mappings ORDER BY created_at DESC').all();
  res.json(rows);
});

app.post('/api/mappings', (req, res) => {
  const { lava_product_name, lava_offer_id, gc_action, gc_group_name, gc_offer_code, gc_product_title } = req.body;
  if (!lava_product_name) return res.status(400).json({ error: 'Название продукта обязательно' });
  const id = uuidv4();
  db.prepare(`
    INSERT INTO mappings (id, lava_product_name, lava_offer_id, gc_action, gc_group_name, gc_offer_code, gc_product_title)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, lava_product_name, lava_offer_id || '', gc_action || 'both', gc_group_name || '', gc_offer_code || '', gc_product_title || '');
  const row = db.prepare('SELECT * FROM mappings WHERE id = ?').get(id);
  res.json(row);
});

app.put('/api/mappings/:id', (req, res) => {
  const { lava_product_name, lava_offer_id, gc_action, gc_group_name, gc_offer_code, gc_product_title, is_active } = req.body;
  db.prepare(`
    UPDATE mappings SET
      lava_product_name = COALESCE(?, lava_product_name),
      lava_offer_id = COALESCE(?, lava_offer_id),
      gc_action = COALESCE(?, gc_action),
      gc_group_name = COALESCE(?, gc_group_name),
      gc_offer_code = COALESCE(?, gc_offer_code),
      gc_product_title = COALESCE(?, gc_product_title),
      is_active = COALESCE(?, is_active)
    WHERE id = ?
  `).run(lava_product_name, lava_offer_id, gc_action, gc_group_name, gc_offer_code, gc_product_title, is_active, req.params.id);
  const row = db.prepare('SELECT * FROM mappings WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Маппинг не найден' });
  res.json(row);
});

app.delete('/api/mappings/:id', (req, res) => {
  const result = db.prepare('DELETE FROM mappings WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Маппинг не найден' });
  res.json({ success: true });
});

// ─── Rules ───

app.get('/api/rules', (req, res) => {
  const rows = db.prepare('SELECT * FROM rules ORDER BY created_at DESC').all();
  res.json(rows.map(r => ({ ...r, actions: JSON.parse(r.actions || '[]') })));
});

app.post('/api/rules', (req, res) => {
  const { name, condition_type, condition_value, actions } = req.body;
  if (!condition_value) return res.status(400).json({ error: 'Условие обязательно' });
  const id = uuidv4();
  db.prepare(`
    INSERT INTO rules (id, name, condition_type, condition_value, actions)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, name || '', condition_type || 'product_equals', condition_value, JSON.stringify(actions || []));
  const row = db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
  res.json({ ...row, actions: JSON.parse(row.actions) });
});

app.put('/api/rules/:id', (req, res) => {
  const { name, condition_type, condition_value, actions, is_active } = req.body;
  const existing = db.prepare('SELECT * FROM rules WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Правило не найдено' });
  db.prepare(`
    UPDATE rules SET
      name = COALESCE(?, name),
      condition_type = COALESCE(?, condition_type),
      condition_value = COALESCE(?, condition_value),
      actions = COALESCE(?, actions),
      is_active = COALESCE(?, is_active)
    WHERE id = ?
  `).run(name, condition_type, condition_value, actions ? JSON.stringify(actions) : null, is_active, req.params.id);
  const row = db.prepare('SELECT * FROM rules WHERE id = ?').get(req.params.id);
  res.json({ ...row, actions: JSON.parse(row.actions) });
});

app.delete('/api/rules/:id', (req, res) => {
  const result = db.prepare('DELETE FROM rules WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Правило не найдено' });
  res.json({ success: true });
});

// ─── GetCourse Groups ───

app.get('/api/gc/groups', async (req, res) => {
  const settings = db.prepare('SELECT gc_account, gc_secret FROM settings WHERE id = ?').get('main');
  if (!settings?.gc_account || !settings?.gc_secret) return res.status(400).json({ error: 'GetCourse не настроен' });
  try {
    const body = new URLSearchParams({ key: settings.gc_secret });
    const gcRes = await fetch(`https://${settings.gc_account}.getcourse.ru/pl/api/account/groups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    if (!gcRes.ok) return res.status(gcRes.status).json({ error: `GC HTTP ${gcRes.status}` });
    const data = await gcRes.json();
    res.json(data.info || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Logs ───

app.get('/api/logs', (req, res) => {
  const { page = 1, limit = 50, status, date_from, date_to } = req.query;
  let where = [];
  let params = [];

  if (status) { where.push('gc_status = ?'); params.push(status); }
  if (date_from) { where.push('processed_at >= ?'); params.push(date_from); }
  if (date_to) { where.push('processed_at <= ?'); params.push(date_to + 'T23:59:59'); }

  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const total = db.prepare(`SELECT COUNT(*) as cnt FROM sync_log ${whereClause}`).get(...params).cnt;
  const rows = db.prepare(`SELECT * FROM sync_log ${whereClause} ORDER BY processed_at DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);

  res.json({ items: rows, total, page: parseInt(page), limit: parseInt(limit) });
});

app.get('/api/logs/stats', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as cnt FROM sync_log').get().cnt;
  const success = db.prepare("SELECT COUNT(*) as cnt FROM sync_log WHERE gc_status = 'success'").get().cnt;
  const errors = db.prepare("SELECT COUNT(*) as cnt FROM sync_log WHERE gc_status = 'error'").get().cnt;
  const lastSync = db.prepare('SELECT last_sync_at FROM settings WHERE id = ?').get('main')?.last_sync_at || '';
  res.json({ total, success, errors, last_sync_at: lastSync });
});

app.delete('/api/logs/clear', (req, res) => {
  db.prepare('DELETE FROM sync_log').run();
  db.prepare("UPDATE settings SET last_sync_at = '' WHERE id = 'main'").run();
  res.json({ success: true });
});

// ─── LavaTop Products ───

app.get('/api/lava/products', async (req, res) => {
  const settings = db.prepare('SELECT lava_api_key FROM settings WHERE id = ?').get('main');
  if (!settings?.lava_api_key) return res.status(400).json({ error: 'API ключ LavaTop не настроен' });

  try {
    const lavaRes = await fetch('https://gate.lava.top/api/v2/products', {
      headers: { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' }
    });
    if (!lavaRes.ok) {
      const errText = await lavaRes.text();
      return res.status(lavaRes.status).json({ error: `LavaTop API: ${errText}` });
    }
    const data = await lavaRes.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/lava/all-products', async (req, res) => {
  const settings = db.prepare('SELECT lava_api_key FROM settings WHERE id = ?').get('main');
  if (!settings?.lava_api_key) return res.status(400).json({ error: 'API ключ LavaTop не настроен' });
  const headers = { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' };
  const products = new Map();
  try {
    // From /v2/products with feedVisibility=ALL (paginate via nextPage)
    let url = 'https://gate.lava.top/api/v2/products?feedVisibility=ALL&page=1&size=100';
    for (let i = 0; i < 10 && url; i++) {
      const pRes = await fetch(url, { headers });
      if (!pRes.ok) break;
      const pData = await pRes.json();
      for (const p of (pData.items || [])) {
        products.set(p.id, { id: p.id, name: p.title, type: p.type, offers: p.offers || [] });
      }
      url = pData.nextPage || '';
    }
    res.json(Array.from(products.values()));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Restore (import all LavaTop sales without GC processing) ───

app.post('/api/sync/restore', async (req, res) => {
  const settings = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');
  if (!settings?.lava_api_key) return res.status(400).json({ error: 'API ключ LavaTop не настроен' });

  const headers = { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' };
  let imported = 0;
  let skipped = 0;

  try {
    // Clear existing log
    db.prepare('DELETE FROM sync_log').run();
    db.prepare("UPDATE settings SET last_sync_at = '' WHERE id = 'main'").run();

    // Get all products from sales overview
    const salesOverviewRes = await fetch('https://gate.lava.top/api/v1/sales/?page=1&size=100', { headers });
    if (!salesOverviewRes.ok) throw new Error(`LavaTop sales error: ${salesOverviewRes.status}`);
    const salesOverview = await salesOverviewRes.json();
    const products = (salesOverview.items || []).map(s => ({ id: s.productId, title: s.title }));

    // For each product, fetch all sales
    for (const product of products) {
      let page = 1;
      let totalPages = 1;

      while (page <= totalPages) {
        const salesRes = await fetch(`https://gate.lava.top/api/v1/sales/${product.id}?page=${page}&size=50`, { headers });
        if (!salesRes.ok) { page++; continue; }

        const salesData = await salesRes.json();
        totalPages = salesData.totalPages || 1;

        for (const sale of (salesData.items || [])) {
          const saleUniqueId = `${sale.id}_${sale.created}`;
          const buyerEmail = sale.buyer?.email || '';
          const productName = sale.product?.name || product.title || '';
          const amount = sale.amountTotal?.amount || 0;
          const currency = sale.amountTotal?.currency || '';
          const status = sale.status || 'unknown';

          try {
            db.prepare(`
              INSERT OR IGNORE INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              uuidv4(), saleUniqueId, buyerEmail, productName, amount, currency,
              status === 'completed' ? 'imported' : status,
              '', sale.created || new Date().toISOString()
            );
            imported++;
          } catch (e) { skipped++; }
        }
        page++;
      }
    }

    res.json({ imported, skipped });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Manual Sync ───

app.post('/api/sync', async (req, res) => {
  try {
    const result = await syncPayments(true);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Sync Logic ───

async function syncPayments(manual = false) {
  const settings = db.prepare('SELECT * FROM settings WHERE id = ?').get('main');

  if (!manual && !settings.is_active) {
    return { skipped: true, reason: 'Синхронизация отключена' };
  }

  if (!settings.lava_api_key || !settings.gc_account || !settings.gc_secret) {
    return { skipped: true, reason: 'API ключи не настроены' };
  }

  let processed = 0;
  let errors = 0;
  let skipped = 0;
  let totalSales = 0;

  const headers = { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' };
  const mappings = db.prepare('SELECT * FROM mappings WHERE is_active = 1').all();
  const rules = db.prepare('SELECT * FROM rules WHERE is_active = 1').all().map(r => ({ ...r, actions: JSON.parse(r.actions || '[]') }));

  try {
    // Step 1: Get product list from sales overview (includes deleted products)
    const salesOverviewRes = await fetch('https://gate.lava.top/api/v1/sales/?page=1&size=100', { headers });
    if (!salesOverviewRes.ok) throw new Error(`LavaTop sales error: ${salesOverviewRes.status}`);
    const salesOverview = await salesOverviewRes.json();
    const products = (salesOverview.items || []).map(s => ({ id: s.productId, title: s.title }));

    // Step 2: For each product, fetch sales with pagination
    for (const product of products) {
      let page = 1;
      let totalPages = 1;

      while (page <= totalPages) {
        const salesUrl = `https://gate.lava.top/api/v1/sales/${product.id}?page=${page}&size=50`;
        const salesRes = await fetch(salesUrl, { headers });
        if (!salesRes.ok) { page++; continue; }

        const salesData = await salesRes.json();
        totalPages = salesData.totalPages || 1;
        const sales = salesData.items || [];

        for (const sale of sales) {
          totalSales++;

          // Unique key: sale id + created timestamp (LavaTop reuses IDs across sales)
          const saleUniqueId = `${sale.id}_${sale.created}`;

          // Skip already processed
          const existing = db.prepare('SELECT id FROM sync_log WHERE lava_invoice_id = ?').get(saleUniqueId);
          if (existing) { skipped++; continue; }

          // Only process completed sales
          if (sale.status !== 'completed') { skipped++; continue; }

          const buyerEmail = sale.buyer?.email;
          const productName = sale.product?.name || product.title || '';
          const productId = sale.product?.id || product.id || '';
          const amount = sale.amountTotal?.amount || 0;
          const currency = sale.amountTotal?.currency || '';

          if (!buyerEmail) {
            db.prepare(`
              INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
              VALUES (?, ?, ?, ?, ?, ?, 'error', ?, ?)
            `).run(uuidv4(), saleUniqueId, '', productName, amount, currency, 'Email покупателя отсутствует', sale.created || new Date().toISOString());
            errors++;
            continue;
          }

          // Find matching rule first, then fall back to mapping
          // Pre-check: resolve user status in GC if any rule needs it
          let gcUserStatus = null; // null = not checked, 'added' = new, 'updated' = exists
          const needsGcCheck = rules.some(r => r.condition_type === 'user_exists_gc' || r.condition_type === 'user_not_exists_gc');
          if (needsGcCheck) {
            try {
              const checkRes = await gcApiCall(settings, 'users', { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } });
              gcUserStatus = checkRes.success ? (checkRes.result?.user_status || 'updated') : null;
            } catch (e) { gcUserStatus = null; }
          }

          const matchedRule = rules.find(r => {
            const val = (r.condition_value || '').toLowerCase();
            if (r.condition_type === 'product_equals') return productName.toLowerCase() === val;
            if (r.condition_type === 'product_contains') return productName.toLowerCase().includes(val);
            if (r.condition_type === 'email_contains') return buyerEmail.toLowerCase().includes(val);
            if (r.condition_type === 'email_equals') return buyerEmail.toLowerCase() === val;
            if (r.condition_type === 'amount_gte') return amount >= parseFloat(r.condition_value);
            if (r.condition_type === 'amount_lte') return amount <= parseFloat(r.condition_value);
            if (r.condition_type === 'user_exists_gc') return gcUserStatus === 'updated';
            if (r.condition_type === 'user_not_exists_gc') return gcUserStatus === 'added';
            return false;
          });

          const mapping = !matchedRule ? mappings.find(m =>
            (m.lava_product_name && productName.toLowerCase().includes(m.lava_product_name.toLowerCase())) ||
            (m.lava_offer_id && (m.lava_offer_id === productId || m.lava_offer_id === sale.id))
          ) : null;

          if (!matchedRule && !mapping) {
            db.prepare(`
              INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
              VALUES (?, ?, ?, ?, ?, ?, 'error', ?, ?)
            `).run(uuidv4(), saleUniqueId, buyerEmail, productName, amount, currency, 'Правило/маппинг не найдены для продукта', sale.created || new Date().toISOString());
            errors++;
            continue;
          }

          // Process in GetCourse
          let gcUserId = '';
          let gcDealId = '';
          let gcError = '';
          let gcStatus = 'success';

          try {
            if (matchedRule) {
              const result = await executeActions(matchedRule.actions, settings, buyerEmail, amount, productName, matchedRule.name, 'sync');
              gcUserId = result.gcUserId;
              gcDealId = result.gcDealId;
            } else {
              // Legacy mapping logic
              if (mapping.gc_action === 'group' || mapping.gc_action === 'both') {
                const userParams = { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } };
                if (mapping.gc_group_name) userParams.user.group_name = [mapping.gc_group_name];
                const userRes = await gcApiCall(settings, 'users', userParams);
                if (userRes.success) {
                  gcUserId = String(userRes.result?.user_id || '');
                  logAction('added_to_group', buyerEmail, { user_id: gcUserId, group: mapping.gc_group_name || '', product: productName });
                } else throw new Error(userRes.error_message || 'Ошибка создания пользователя');
              }
              if (mapping.gc_action === 'deal' || mapping.gc_action === 'both') {
                const dealParams = { user: { email: buyerEmail }, deal: { deal_cost: amount, deal_is_paid: 'yes' }, system: { refresh_if_exists: 1 } };
                if (mapping.gc_offer_code) dealParams.deal.offer_code = mapping.gc_offer_code;
                if (mapping.gc_product_title) dealParams.deal.product_title = mapping.gc_product_title;
                const dealRes = await gcApiCall(settings, 'deals', dealParams);
                if (dealRes.success) {
                  gcDealId = String(dealRes.result?.deal_id || '');
                  logAction('product_granted', buyerEmail, { deal_id: gcDealId, offer_code: mapping.gc_offer_code, product: productName });
                } else throw new Error(dealRes.error_message || 'Ошибка создания заказа');
              }
            }
          } catch (e) {
            gcStatus = 'error';
            gcError = e.message;
            logAction('gc_error', buyerEmail, { product: productName, rule: matchedRule?.name || '' }, 'error', e.message);
          }

          db.prepare(`
            INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_user_id, gc_deal_id, gc_status, gc_error, processed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(uuidv4(), saleUniqueId, buyerEmail, productName, amount, currency, gcUserId, gcDealId, gcStatus, gcError, sale.created || new Date().toISOString());

          if (gcStatus === 'success') processed++;
          else errors++;
        }

        page++;
      }
    }

    // Update last sync time
    db.prepare("UPDATE settings SET last_sync_at = ? WHERE id = 'main'").run(new Date().toISOString());

    return { processed, errors, skipped, total: totalSales };
  } catch (e) {
    console.error('Sync error:', e.message);
    return { error: e.message, processed, errors };
  }
}

// ─── Shared Action Executor (used by webhook & sync) ───
async function executeActions(actions, settings, buyerEmail, amount, productName, ruleName, source) {
  let gcUserId = '', gcDealId = '';
  for (const action of actions) {
    if (action.type === 'condition') {
      // Check user existence in GC
      const checkRes = await gcApiCall(settings, 'users', { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } });
      const userStatus = checkRes.success ? (checkRes.result?.user_status || 'updated') : null;
      let conditionMet = false;
      if (action.condition === 'user_exists_gc') conditionMet = userStatus === 'updated';
      else if (action.condition === 'user_not_exists_gc') conditionMet = userStatus !== 'updated';
      const branchActions = conditionMet ? (action.then_actions || []) : (action.else_actions || []);
      logAction('condition_checked', buyerEmail, { condition: action.condition, result: conditionMet, branch: conditionMet ? 'then' : 'else', product: productName, rule: ruleName, source });
      const result = await executeActions(branchActions, settings, buyerEmail, amount, productName, ruleName, source);
      gcUserId = result.gcUserId || gcUserId;
      gcDealId = result.gcDealId || gcDealId;
    } else if (action.type === 'authorize') {
      const userRes = await gcApiCall(settings, 'users', { user: { email: buyerEmail }, system: { refresh_if_exists: 1 } });
      if (userRes.success) {
        gcUserId = String(userRes.result?.user_id || '');
        const isNew = userRes.result?.user_status === 'added';
        logAction(isNew ? 'user_created' : 'user_authorized', buyerEmail, { user_id: gcUserId, product: productName, rule: ruleName, source });
      } else throw new Error(userRes.error_message || 'Ошибка авторизации пользователя');
    } else if (action.type === 'add_to_group') {
      const userRes = await gcApiCall(settings, 'users', { user: { email: buyerEmail, group_name: [action.group_name] }, system: { refresh_if_exists: 1 } });
      if (userRes.success) {
        gcUserId = String(userRes.result?.user_id || '');
        logAction('added_to_group', buyerEmail, { user_id: gcUserId, group: action.group_name, product: productName, rule: ruleName, source });
      } else throw new Error(userRes.error_message || 'Ошибка добавления в группу');
    } else if (action.type === 'grant_product') {
      const dealParams = { user: { email: buyerEmail }, deal: { deal_cost: amount, deal_is_paid: 'yes' }, system: { refresh_if_exists: 1 } };
      if (action.offer_code) dealParams.deal.offer_code = action.offer_code;
      if (action.product_title) dealParams.deal.product_title = action.product_title;
      const dealRes = await gcApiCall(settings, 'deals', dealParams);
      if (dealRes.success) {
        gcDealId = String(dealRes.result?.deal_id || '');
        logAction('product_granted', buyerEmail, { deal_id: gcDealId, offer_code: action.offer_code, product_title: action.product_title, product: productName, rule: ruleName, source });
      } else throw new Error(dealRes.error_message || 'Ошибка выдачи продукта');
    }
  }
  return { gcUserId, gcDealId };
}

async function gcApiCall(settings, endpoint, params) {
  const paramsBase64 = Buffer.from(JSON.stringify(params)).toString('base64');
  const body = new URLSearchParams({ action: 'add', key: settings.gc_secret, params: paramsBase64 });

  const res = await fetch(`https://${settings.gc_account}.getcourse.ru/pl/api/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!res.ok) {
    throw new Error(`GetCourse HTTP ${res.status}`);
  }

  return await res.json();
}

// ─── Payment Pages ───

// Create invoice via LavaTop API
app.post('/api/create-invoice', async (req, res) => {
  const { email, offerId, currency } = req.body;
  if (!email || !offerId) return res.status(400).json({ error: 'Email и offerId обязательны' });

  const settings = db.prepare('SELECT lava_api_key FROM settings WHERE id = ?').get('main');
  if (!settings?.lava_api_key) return res.status(400).json({ error: 'API ключ LavaTop не настроен' });

  try {
    const body = { email, offerId, currency: currency || 'EUR' };
    const lavaRes = await fetch('https://gate.lava.top/api/v3/invoice', {
      method: 'POST',
      headers: {
        'X-Api-Key': settings.lava_api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });
    if (!lavaRes.ok) {
      const errText = await lavaRes.text();
      return res.status(lavaRes.status).json({ error: `LavaTop: ${errText}` });
    }
    const data = await lavaRes.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Payment page
app.get('/pay/:offerId', async (req, res) => {
  const { offerId } = req.params;
  const settings = db.prepare('SELECT lava_api_key FROM settings WHERE id = ?').get('main');

  // Find product info for this offer
  let productTitle = '';
  let prices = [];
  if (settings?.lava_api_key) {
    try {
      const headers = { 'X-Api-Key': settings.lava_api_key, 'Accept': 'application/json' };
      let url = 'https://gate.lava.top/api/v2/products?feedVisibility=ALL&page=1&size=100';
      for (let i = 0; i < 10 && url; i++) {
        const pRes = await fetch(url, { headers });
        if (!pRes.ok) break;
        const pData = await pRes.json();
        for (const p of (pData.items || [])) {
          for (const o of (p.offers || [])) {
            if (o.id === offerId) {
              productTitle = p.title || o.name || '';
              prices = o.prices || [];
            }
          }
        }
        if (productTitle) break;
        url = pData.nextPage || '';
      }
    } catch (e) { console.error('Pay page product lookup:', e.message); }
  }

  const priceDisplay = prices.map(p => `${p.amount} ${p.currency}`).join(' / ') || '';

  res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${productTitle || 'Оплата'}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e1e4e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
.pay-card { background: #161b22; border: 1px solid #30363d; border-radius: 16px; padding: 40px; width: 420px; max-width: 90vw; text-align: center; }
.pay-card h1 { font-size: 22px; margin-bottom: 8px; }
.pay-card .price { color: #7c5dfa; font-size: 18px; font-weight: 600; margin-bottom: 24px; }
.pay-card .form-group { text-align: left; margin-bottom: 16px; }
.pay-card label { display: block; font-size: 13px; color: #8b949e; margin-bottom: 6px; }
.pay-card input, .pay-card select { width: 100%; padding: 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #e1e4e8; font-size: 15px; outline: none; }
.pay-card input:focus, .pay-card select:focus { border-color: #7c5dfa; }
.pay-btn { width: 100%; padding: 14px; background: #7c5dfa; color: #fff; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 8px; }
.pay-btn:hover { background: #6c4de6; }
.pay-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.error { color: #f85149; font-size: 13px; margin-top: 12px; display: none; }
.spinner { display: inline-block; width: 18px; height: 18px; border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff; border-radius: 50%; animation: spin 0.6s linear infinite; vertical-align: middle; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="pay-card">
  <h1>${productTitle || 'Оплата'}</h1>
  <div class="price">${priceDisplay}</div>
  <div class="form-group">
    <label>Ваш email</label>
    <input type="email" id="email" placeholder="email@example.com" required>
  </div>
  <div class="form-group">
    <label>Валюта</label>
    <select id="currency">
      ${prices.map(p => `<option value="${p.currency}">${p.currency} — ${p.amount}</option>`).join('') || '<option value="EUR">EUR</option><option value="USD">USD</option><option value="RUB">RUB</option>'}
    </select>
  </div>
  <button class="pay-btn" id="payBtn" onclick="pay()">Оплатить</button>
  <div class="error" id="error"></div>
</div>
<script>
async function pay() {
  const email = document.getElementById('email').value.trim();
  if (!email) { showError('Введите email'); return; }
  const currency = document.getElementById('currency').value;
  const btn = document.getElementById('payBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Создание платежа...';
  hideError();
  try {
    const res = await fetch('/api/create-invoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, offerId: '${offerId}', currency })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Ошибка');
    if (data.paymentUrl) {
      window.location.href = data.paymentUrl;
    } else {
      showError('Не удалось получить ссылку на оплату');
    }
  } catch (e) {
    showError(e.message);
  }
  btn.disabled = false;
  btn.textContent = 'Оплатить';
}
function showError(msg) { const el = document.getElementById('error'); el.textContent = msg; el.style.display = 'block'; }
function hideError() { document.getElementById('error').style.display = 'none'; }
</script>
</body>
</html>`);
});

// ─── Polling ───

let pollTimer = null;

function restartPolling() {
  if (pollTimer) clearInterval(pollTimer);
  const settings = db.prepare('SELECT poll_interval, is_active FROM settings WHERE id = ?').get('main');
  if (settings?.is_active) {
    const interval = Math.max(30, settings.poll_interval || 120) * 1000;
    pollTimer = setInterval(() => syncPayments(false), interval);
    console.log(`Polling started: every ${interval / 1000}s`);
  } else {
    console.log('Polling stopped (sync disabled)');
  }
}

// ─── Start ───

app.listen(PORT, () => {
  console.log(`LavaTop ↔ GetCourse integration running on http://localhost:${PORT}`);
  restartPolling();
});
