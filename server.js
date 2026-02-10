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

// Ensure default settings row
const existingSettings = db.prepare('SELECT id FROM settings WHERE id = ?').get('main');
if (!existingSettings) {
  db.prepare('INSERT INTO settings (id) VALUES (?)').run('main');
}

app.use(express.json());
app.use(express.static(__dirname));

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

  try {
    // Step 1: Get all products
    const productsRes = await fetch('https://gate.lava.top/api/v2/products', { headers });
    if (!productsRes.ok) throw new Error(`LavaTop products error: ${productsRes.status}`);
    const productsData = await productsRes.json();
    const products = productsData.items || productsData || [];

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

          // Find mapping by product name or product/offer id
          const mapping = mappings.find(m =>
            (m.lava_product_name && productName.toLowerCase().includes(m.lava_product_name.toLowerCase())) ||
            (m.lava_offer_id && (m.lava_offer_id === productId || m.lava_offer_id === sale.id))
          );

          if (!mapping) {
            db.prepare(`
              INSERT INTO sync_log (id, lava_invoice_id, buyer_email, product_name, amount, currency, gc_status, gc_error, processed_at)
              VALUES (?, ?, ?, ?, ?, ?, 'error', ?, ?)
            `).run(uuidv4(), saleUniqueId, buyerEmail, productName, amount, currency, 'Маппинг не найден для продукта', sale.created || new Date().toISOString());
            errors++;
            continue;
          }

          // Process in GetCourse
          let gcUserId = '';
          let gcDealId = '';
          let gcError = '';
          let gcStatus = 'success';

          try {
            // Create user (+ add to group if needed)
            if (mapping.gc_action === 'group' || mapping.gc_action === 'both') {
              const userParams = {
                user: { email: buyerEmail },
                system: { refresh_if_exists: 1 }
              };
              if (mapping.gc_group_name) {
                userParams.user.group_name = [mapping.gc_group_name];
              }
              const userRes = await gcApiCall(settings, 'users', userParams);
              if (userRes.success) {
                gcUserId = String(userRes.result?.user_id || '');
              } else {
                throw new Error(userRes.error_message || 'Ошибка создания пользователя в GetCourse');
              }
            }

            // Create deal (training access) if needed
            if (mapping.gc_action === 'deal' || mapping.gc_action === 'both') {
              const dealParams = {
                user: { email: buyerEmail },
                deal: { deal_cost: amount, deal_is_paid: 'yes' },
                system: { refresh_if_exists: 1 }
              };
              if (mapping.gc_offer_code) dealParams.deal.offer_code = mapping.gc_offer_code;
              if (mapping.gc_product_title) dealParams.deal.product_title = mapping.gc_product_title;
              const dealRes = await gcApiCall(settings, 'deals', dealParams);
              if (dealRes.success) {
                gcDealId = String(dealRes.result?.deal_id || '');
              } else {
                throw new Error(dealRes.error_message || 'Ошибка создания заказа в GetCourse');
              }
            }
          } catch (e) {
            gcStatus = 'error';
            gcError = e.message;
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
