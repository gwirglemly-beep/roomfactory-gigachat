const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const dns = require('dns');
const { GoogleGenAI } = require('@google/genai');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

dns.setDefaultResultOrder('ipv4first');

const app = express();
app.set('trust proxy', true);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024, fieldSize: 5 * 1024 * 1024 } });

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Expose-Headers', 'X-Furniture-List, X-Style-Key, X-Matched-Items, X-Used-Items');
  // Базовые заголовки безопасности (без доп. npm-пакетов, чтобы не трогать package.json).
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.method === 'OPTIONS') { res.sendStatus(200); return; }
  next();
});

// Простое ограничение числа попыток в памяти процесса: защита от перебора кода
// подтверждения/пароля и от брутфорса логина. Не требует новых npm-пакетов.
// Если на Render несколько процессов сразу — лимит считается per-процесс, этого
// достаточно как первой защиты; для строгого лимита на всех процессах нужна БД/Redis.
const rateBuckets = new Map();
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  bucket.count += 1;
  return bucket.count > max;
}
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) if (now > bucket.resetAt) rateBuckets.delete(key);
}, 10 * 60 * 1000).unref();

// name — имя эндпоинта (отдельный счётчик на каждый), max — сколько попыток разрешено
// за windowMs миллисекунд на один IP. При превышении — 429 Too Many Requests.
function authRateLimit(name, max, windowMs) {
  return (req, res, next) => {
    const key = name + ':' + (req.ip || req.socket.remoteAddress || 'unknown');
    if (rateLimited(key, max, windowMs)) {
      res.status(429).json({ error: 'too_many_attempts' });
      return;
    }
    next();
  };
}

const OAUTH_URL = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth';
const API_BASE = 'https://gigachat.devices.sberbank.ru/api/v1';
const AUTH_KEY = process.env.GIGACHAT_AUTH_KEY;

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-3.1-flash-image';

// Лимит бесплатных генераций: GEN_LIMIT_TOTAL за всё время на аккаунт (счётчик в БД, users.generations_used).
// Для гостей без входа — тот же лимит на IP (в памяти сервера, сбрасывается при перезапуске).
// DAILY_LIMIT_GLOBAL — только защита бюджета: общий потолок генераций в сутки.
const GEN_LIMIT_TOTAL = parseInt(process.env.GEN_LIMIT_TOTAL || '3', 10);
const DAILY_LIMIT_GLOBAL = parseInt(process.env.DAILY_LIMIT_GLOBAL || '300', 10);
// UNLIMITED_EMAILS — почты через запятую (в Render), у которых нет лимита на аккаунт (владелец, тестирование).
const UNLIMITED_EMAILS = (process.env.UNLIMITED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
let usageDay = '';
let usageGlobal = 0;
const usageByIp = new Map();

function moscowDay() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Europe/Moscow' });
}

async function getOptionalUser(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  const { rows } = await pool.query(
    'SELECT s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()',
    [hashToken(token)]
  );
  return rows.length ? { id: rows[0].user_id, email: rows[0].email } : null;
}

async function reserveGeneration(req, res) {
  const day = moscowDay();
  if (day !== usageDay) { usageDay = day; usageGlobal = 0; }
  if (usageGlobal >= DAILY_LIMIT_GLOBAL) { res.status(429).json({ error: 'global_limit' }); return null; }

  const user = await getOptionalUser(req);
  if (user) {
    if (UNLIMITED_EMAILS.includes(String(user.email || '').toLowerCase())) { usageGlobal++; return { unlimited: true }; }
    const userId = user.id;
    const { rows } = await pool.query(
      'UPDATE users SET generations_used = generations_used + 1 WHERE id = $1 AND generations_used < $2 RETURNING generations_used',
      [userId, GEN_LIMIT_TOTAL]
    );
    if (!rows.length) { res.status(429).json({ error: 'limit_reached' }); return null; }
    usageGlobal++;
    return { userId };
  }

  const ip = req.ip || 'unknown';
  const used = usageByIp.get(ip) || 0;
  if (used >= GEN_LIMIT_TOTAL) { res.status(429).json({ error: 'limit_reached' }); return null; }
  usageByIp.set(ip, used + 1);
  usageGlobal++;
  return { ip };
}

async function releaseGeneration(reserved) {
  if (!reserved) return;
  try {
    if (reserved.userId) {
      await pool.query('UPDATE users SET generations_used = GREATEST(generations_used - 1, 0) WHERE id = $1', [reserved.userId]);
    } else if (reserved.ip) {
      const used = usageByIp.get(reserved.ip) || 0;
      if (used > 0) usageByIp.set(reserved.ip, used - 1);
    }
  } catch (e) { console.error(e); }
  if (usageGlobal > 0) usageGlobal--;
}

function parseUserReference(dataUrl) {
  if (typeof dataUrl !== 'string' || dataUrl.length > 4 * 1024 * 1024) return null;
  const m = dataUrl.match(/^data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)$/i);
  if (!m) return null;
  return { buffer: Buffer.from(m[2], 'base64'), mimetype: m[1] };
}

let geminiClient = null;
function getGeminiClient() {
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY is not set on the server');
  if (!geminiClient) geminiClient = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  return geminiClient;
}

let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiresAt - 10000) return cachedToken;
  const resp = await fetch(OAUTH_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'RqUID': crypto.randomUUID(),
      'Authorization': 'Basic ' + AUTH_KEY
    },
    body: 'scope=GIGACHAT_API_PERS'
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('oauth ' + resp.status + ': ' + text);
  const data = JSON.parse(text);
  cachedToken = data.access_token;
  tokenExpiresAt = data.expires_at;
  return cachedToken;
}

async function uploadImage(token, buffer, filename, mimetype) {
  const form = new FormData();
  form.append('file', new Blob([buffer], { type: mimetype || 'image/jpeg' }), filename || 'room.jpg');
  form.append('purpose', 'general');
  const resp = await fetch(API_BASE + '/files', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token },
    body: form
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('upload ' + resp.status + ': ' + text);
  const data = JSON.parse(text);
  return data.id;
}

const CANONICAL_STYLE_KEYS = ['scandinavian', 'minimalism', 'loft', 'classic', 'japandi', 'boho'];

async function classifyStyleKey(token, fileId) {
  try {
    const resp = await fetch(API_BASE + '/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'GigaChat-2-Max',
        messages: [{
          role: 'user',
          content: 'Посмотри на интерьер комнаты на фото и выбери ОДНО ближайшее слово из списка, которое лучше всего описывает стиль: scandinavian, minimalism, loft, classic, japandi, boho. Ответь только этим одним словом на английском, без пояснений.',
          attachments: [fileId]
        }]
      })
    });
    const text = await resp.text();
    if (!resp.ok) return 'scandinavian';
    const data = JSON.parse(text);
    const content = ((data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '').toLowerCase();
    return CANONICAL_STYLE_KEYS.find(k => content.includes(k)) || 'scandinavian';
  } catch (e) {
    return 'scandinavian';
  }
}

const FURNITURE_TYPE_WORDS = ['диван', 'кресло', 'кровать', 'стол', 'стул', 'шкаф', 'полка', 'зеркало', 'ковёр', 'светильник', 'тумба', 'комод', 'пуф'];
const FURNITURE_COLOR_WORDS = ['белый', 'бежевый', 'серый', 'чёрный', 'коричневый', 'зелёный', 'синий', 'розовый', 'жёлтый'];

async function describeGeneratedFurniture(token, fileId) {
  try {
    const resp = await fetch(API_BASE + '/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'GigaChat-2-Max',
        messages: [{
          role: 'user',
          content: 'Ты видишь готовую картинку интерьера комнаты. Перечисли всю мебель на ней, не более 5 предметов. ' +
            'Для типа мебели используй ровно одно слово из этого списка: ' + FURNITURE_TYPE_WORDS.join(', ') + ' — выбери максимально близкое слово, даже если предмет не идеально ему соответствует. ' +
            'Для цвета используй ровно одно слово из этого списка: ' + FURNITURE_COLOR_WORDS.join(', ') + ' — выбери ближайший цвет. ' +
            'Не пиши ничего, кроме списка. Формат строго построчно: тип - цвет. Пример:\nкровать - коричневый\nстол - белый\nполка - коричневый',
          attachments: [fileId]
        }]
      })
    });
    const text = await resp.text();
    if (!resp.ok) return [];
    const data = JSON.parse(text);
    const content = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    const items = [];
    content.split('\n').forEach(line => {
      const m = line.match(/([а-яё]+)\s*-\s*([а-яё]+)/i);
      if (!m) return;
      const type = m[1].toLowerCase().trim();
      const color = m[2].toLowerCase().trim();
      if (FURNITURE_TYPE_WORDS.includes(type) && FURNITURE_COLOR_WORDS.includes(color)) items.push({ type, color });
    });
    return items;
  } catch (e) {
    return [];
  }
}

function findGeminiImagePart(response) {
  const candidates = response.candidates || [];
  for (const c of candidates) {
    const parts = (c.content && c.content.parts) || [];
    for (const p of parts) {
      if (p.inlineData && p.inlineData.data) return p.inlineData;
    }
  }
  return null;
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function generateWithGemini(promptText, images) {
  const client = getGeminiClient();
  const parts = [{ text: promptText }];
  images.forEach(img => {
    parts.push({ inlineData: { mimeType: img.mimetype || 'image/jpeg', data: img.buffer.toString('base64') } });
  });

  const maxAttempts = 5;
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await client.models.generateContent({
        model: GEMINI_MODEL,
        contents: [{ role: 'user', parts }]
      });
      const part = findGeminiImagePart(response);
      if (!part) throw new Error('no image in gemini response: ' + JSON.stringify(response).slice(0, 800));
      return { buffer: Buffer.from(part.data, 'base64'), mimeType: part.mimeType || 'image/jpeg' };
    } catch (err) {
      lastErr = err;
      const status = err && err.status;
      const retryable = status === 503 || status === 429 || status === 500;
      if (!retryable || attempt === maxAttempts) throw err;
      await sleep(attempt * 3000);
    }
  }
  throw lastErr;
}

const ALLOWED_IMAGE_HOSTS = ['hoff.ru', 'www.hoff.ru'];

function isAllowedImageUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    return ALLOWED_IMAGE_HOSTS.includes(u.hostname.toLowerCase());
  } catch (e) {
    return false;
  }
}

async function fetchImageAsPart(url) {
  if (!isAllowedImageUrl(url)) return null;
  try {
    const resp = await fetch(url, { redirect: 'error' });
    if (!resp.ok) return null;
    const mimetype = resp.headers.get('content-type') || 'image/jpeg';
    const buffer = Buffer.from(await resp.arrayBuffer());
    return { buffer, mimetype };
  } catch (e) {
    return null;
  }
}

// Проверка: какие из товаров-образцов действительно видны на готовой картинке.
// Если проверка не удалась (ошибка, нет подходящей модели) — возвращаем null, и сайт показывает все выбранные товары, как раньше.
// Текстовые модели Gemini для проверки картинок. gemini-2.5-flash больше недоступна новым пользователям (ответ API 404), поэтому первой идёт gemini-3.8-flash.
// Свою модель можно задать переменной GEMINI_VERIFY_MODEL в Render. Модель, которая вернула 404, больше не пробуется, рабочая запоминается.
const VERIFY_MODELS = [process.env.GEMINI_VERIFY_MODEL, 'gemini-3.8-flash', 'gemini-3.5-flash', 'gemini-2.5-flash', GEMINI_MODEL].filter(Boolean);
const badVerifyModels = new Set();
let goodVerifyModel = null;
function verifyModelOrder() {
  const list = VERIFY_MODELS.filter(m => !badVerifyModels.has(m));
  return goodVerifyModel && list.includes(goodVerifyModel) ? [goodVerifyModel].concat(list.filter(m => m !== goodVerifyModel)) : list;
}

function geminiResponseText(response) {
  const candidates = response.candidates || [];
  let out = '';
  for (const c of candidates) {
    const parts = (c.content && c.content.parts) || [];
    for (const p of parts) if (typeof p.text === 'string') out += p.text;
  }
  return out;
}

async function matchReferencesInResult(resultImage, referenceParts) {
  if (!referenceParts.length) return null;
  const client = getGeminiClient();
  const parts = [{ text: 'The first image is a photo of a designed room. After it come ' + referenceParts.length + ' numbered product photos from a furniture catalog.' }];
  parts.push({ inlineData: { mimeType: resultImage.mimetype || 'image/jpeg', data: resultImage.buffer.toString('base64') } });
  referenceParts.forEach((img, i) => {
    parts.push({ text: 'Product ' + (i + 1) + ':' });
    parts.push({ inlineData: { mimeType: img.mimetype || 'image/jpeg', data: img.buffer.toString('base64') } });
  });
  parts.push({ text: 'Which of the numbered products clearly appear in the designed room photo? A product counts if an item of the same type and a similar color is visible in the room; the exact design may differ slightly. If the type is missing from the room or the color is clearly different, it does NOT count. Answer with ONLY a JSON array of the product numbers, for example [1,3]. If none appear, answer [].' });
  for (const model of VERIFY_MODELS) {
    try {
      const response = await client.models.generateContent({ model, contents: [{ role: 'user', parts }] });
      const m = geminiResponseText(response).match(/\[[\d,\s]*\]/);
      if (m) {
        return JSON.parse(m[0]).filter(n => Number.isInteger(n) && n >= 1 && n <= referenceParts.length).map(n => n - 1);
      }
    } catch (e) {
      console.error('verify failed with model ' + model + ':', e && e.message);
    }
  }
  return null;
}

// Подсказка про способ установки: потолочные светильники вешаем на потолок, настенные вещи — на стену, а не ставим на пол.
function mountHint(name) {
  const n = String(name || '').toLowerCase();
  if (/люстр|потолоч|подвесн|накладн/.test(n)) return ' (ceiling-mounted: it MUST hang from the ceiling, never stand on the floor or furniture)';
  if (/(^|\s)бра(\s|$)|настенн|навесн|вешалк|полка/.test(n)) return ' (wall-mounted: it MUST be fixed on the wall)';
  if (/торшер|напольн/.test(n)) return ' (floor lamp: stands on the floor)';
  if (/зеркал/.test(n)) return ' (mirror: hang it on the wall or lean it against the wall)';
  return '';
}

// Проверка готовой картинки: какие товары из подборки на ней видны и нет ли явного брака (люстра на полу, предметы в воздухе).
// Если брак найден, генерация один раз повторяется с указанием, что исправить.
async function inspectResult(resultImage, referenceParts, palette) {
  const client = getGeminiClient();
  const parts = [{ text: 'The first image is a photo of a designed room.' + (referenceParts.length ? ' After it come ' + referenceParts.length + ' numbered product photos from a furniture catalog.' : '') }];
  parts.push({ inlineData: { mimeType: resultImage.mimetype || 'image/jpeg', data: resultImage.buffer.toString('base64') } });
  referenceParts.forEach((img, i) => {
    parts.push({ text: 'Product ' + (i + 1) + ':' });
    parts.push({ inlineData: { mimeType: img.mimetype || 'image/jpeg', data: img.buffer.toString('base64') } });
  });
  parts.push({ text: 'Task 1: which of the numbered products appear in the designed room photo? A product counts if an item of the same type and a similar color is visible; the exact design may differ slightly. If there are no products, use an empty list. ' +
    'Task 2: does the room photo contain a clear physical or realism defect' + (referenceParts.length ? ', including any numbered product that is clearly missing from the room' : '') + ', for example a ceiling light, chandelier or pendant lamp standing on the floor or on furniture, furniture floating in the air, a wall-mounted item lying on the floor, or a clearly deformed object' + (referenceParts.length ? ', or any piece of furniture or lamp that is NOT one of the numbered products (for example an extra wardrobe, shelf, table, bed or chandelier)' : '') + '? ' +
    (palette ? 'Task 3: the requested color palette is: ' + palette + '. Does the room clearly violate this palette, for example saturated green, red or blue furniture or decor in a monochrome palette? If yes, treat it as a defect and name the offending items and colors. ' : '') +
    'Answer with ONLY a JSON object like {"products":[1,3],"defect":null}. Put a short English sentence in "defect" only for a clear defect or palette violation, otherwise null.' });
  for (const model of verifyModelOrder()) {
    try {
      const response = await client.models.generateContent({ model, contents: [{ role: 'user', parts }] });
      const text = geminiResponseText(response);
      const m = text.match(/\{[\s\S]*\}/);
      if (m) {
        const obj = JSON.parse(m[0]);
        const list = Array.isArray(obj.products) ? obj.products.filter(n => Number.isInteger(n) && n >= 1 && n <= referenceParts.length).map(n => n - 1) : null;
        const defect = typeof obj.defect === 'string' && obj.defect.trim() ? obj.defect.trim().slice(0, 200) : null;
        goodVerifyModel = model;
        return { matched: referenceParts.length ? list : null, defect };
      }
    } catch (e) {
      console.error('inspect failed with model ' + model + ':', e && e.message);
      if (e && (e.status === 404 || /NOT_FOUND|no longer available/i.test(String(e.message || '')))) badVerifyModels.add(model);
    }
  }
  return null;
}

async function generateChecked(promptText, images, referenceParts, palette) {
  let gen = await generateWithGemini(promptText, images);
  let info = await inspectResult({ buffer: gen.buffer, mimetype: gen.mimeType }, referenceParts, palette);
  if (info && info.defect) {
    console.log('defect found, regenerating once:', info.defect);
    try {
      const retry = await generateWithGemini(promptText + ' IMPORTANT: the previous attempt had this defect, fix it this time: ' + info.defect + '. Ceiling lights always hang from the ceiling, all furniture stands naturally on the floor.', images);
      const info2 = await inspectResult({ buffer: retry.buffer, mimetype: retry.mimeType }, referenceParts, palette);
      gen = retry; info = info2;
    } catch (e) {
      console.error('regeneration failed, keeping first result:', e && e.message);
    }
  }
  return { buffer: gen.buffer, mimeType: gen.mimeType, matched: info ? info.matched : null };
}

// Жёсткие правила для запроса к ИИ: мебель только из присланных фото каталога, ничего придуманного, гамма обязательна.
function buildStrictRules(refCount, palette) {
  if (!refCount) return '';
  return 'ABSOLUTE FURNITURE RULE, it overrides every other instruction except the user\'s own written request: the ONLY furniture and lamps allowed in the final room are exactly the ' + refCount + ' catalog products shown in the last ' + refCount + ' reference photos. ' +
    'Reproduce every one of them faithfully and place them naturally in the room. ' +
    'Do NOT invent, imagine, add, copy or substitute ANY other furniture or lighting: no extra or built-in wardrobes or closets, no additional sofas, beds, armchairs, tables, desks, chairs, nightstands, dressers, shelves, shelving units, TV stands, lamps or chandeliers. ' +
    'Remove all furniture that is in the original room photo (including wardrobes, shelves and lamps), unless the user\'s own written request says to keep it. ' +
    'If the room would need an item that is not among the reference products, leave that place empty. ' +
    'You may add only non-furniture decor: wall paint or wallpaper, curtains, plants, pictures, books, cushions and blankets, and a rug only if a rug is among the reference products.' +
    (palette ? ' MANDATORY color palette for the whole room (walls, textiles, decor and furniture): ' + palette + '. Do not use colors outside this palette.' : '');
}

async function fetchReferenceParts(referenceUrls, limit) {
  const urls = (Array.isArray(referenceUrls) ? referenceUrls : []).slice(0, limit);
  const results = await Promise.all(urls.map(fetchImageAsPart));
  const parts = results.filter(Boolean);
  const origIndex = results.map((p, i) => (p ? i : -1)).filter(i => i >= 0);
  return { parts, origIndex };
}

const USER_REFERENCE_RULES = 'Follow the user\'s instruction about this photo precisely: if they say they want exactly this item (for example "точно такой", "именно этот", "exactly this one"), reproduce it faithfully — same shape, same color, same material. If they ask for something similar, place a similar item of the same type and style instead. If their instruction says to change only this one item and keep everything else, do exactly that: modify only what this photo and instruction describe, and leave every other piece of furniture and decor in the room exactly as it is in the original room photo, unchanged.';

app.post('/generate', upload.single('image'), async (req, res) => {
  let reserved = null;
  try {
    if (!req.file) { res.status(400).json({ error: 'no image' }); return; }
    reserved = await reserveGeneration(req, res);
    if (!reserved) return;
    const styleGuidance = req.body.prompt || '';
    const userComment = (req.body.comment || '').trim();

    let referenceUrls = [];
    try { referenceUrls = JSON.parse(req.body.referenceImageUrls || '[]'); } catch (e) {}
    const { parts: referenceParts, origIndex: refOrigIndex } = await fetchReferenceParts(referenceUrls, 8);
    let refNames = [];
    try { refNames = JSON.parse(req.body.referenceNames || '[]'); } catch (e) {}
    const palette = String(req.body.palette || '').slice(0, 200);
    const refNamesText = referenceParts.length ? 'The last ' + referenceParts.length + ' reference photos, in order, are these catalog products: ' + refOrigIndex.map((o, i) => (i + 1) + ') ' + String(refNames[o] || 'product').slice(0, 120) + mountHint(refNames[o])).join('; ') + '. Reproduce each of them as shown. Ceiling lights, chandeliers and pendant lamps always hang from the ceiling; wall-mounted items are always on the wall; never place them on the floor.' : '';
    const userRef = parseUserReference(req.body.userReferenceImage);

    const fullPrompt = [
      'Redesign this exact room photo, using this style guidance as the general direction: ' + styleGuidance + '.',
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the original photo — only change the furniture, decor, materials and colors. Do not extend, widen or reveal any part of the room that is not visible in the original photo — if the photo shows only a corner or a partial view of the room, the result must show that exact same corner or partial view, with the exact same crop and framing, not a wider or different part of the room. Do not invent walls, windows, doors or floor area that are not already visible in the original photo.',
      userComment ? 'THE MOST IMPORTANT INSTRUCTION, follow it exactly and let it override anything below that conflicts with it: the user wrote this specific request: "' + userComment + '". If this request names or implies specific furniture or changes to keep, make, or avoid, follow it precisely. Only the items that this request explicitly asks to keep stay as they are in the original room photo. Every other piece of furniture from the original photo is removed and replaced by the catalog products from the reference photos.' : '',
      userRef ? 'An additional reference photo was supplied by the user, showing the exact item related to their request above. ' + USER_REFERENCE_RULES : '',
      referenceParts.length ? (userComment
        ? 'The last ' + referenceParts.length + ' reference photo(s) show real furniture or decor products from the Hoff catalog, matching the overall style. Use them only to style or furnish parts of the room that the user\'s request above does not already cover or ask to keep — never use them to replace or remove anything the user asked to keep unchanged.'
        : 'Each of the last ' + referenceParts.length + ' reference photo(s) shows a real furniture or decor product (sofa, chair, bed, table, wardrobe, shelf, lamp, rug, etc.) from the Hoff catalog that must appear in the redesigned room, placed appropriately for its type and matching its exact appearance (shape, material, color) as closely as possible. Every reference item should be included — do not skip any of them. All the main furniture pieces (sofas, beds, wardrobes, tables, chairs, storage units) must come strictly from these reference photos — do not invent or substitute any other furniture. You may add small atmospheric details not shown in the references, such as wallpaper or wall paint, curtains, books, notebooks, plants, cushions or other small decor — but keep these secondary and never let them replace or compete with the main reference furniture. Never add unrelated objects that were not in the original room photo and are not furniture or plain decor — no appliances, no pet items, no electronics, nothing that was not requested. Choose the wall color or wallpaper, floor tone and any added decor so they harmonize with the color palette of the reference furniture — do not use a wall color that clashes with it. The requested color palette is MANDATORY for the whole room: walls, floor accents, textiles, decor AND furniture. Keep the shape and design of each reference product, but if its color clearly clashes with the requested palette, recolor that item to a matching palette color. Strictly avoid any saturated color that is not part of the palette.') : '',
      'This is the most important part regardless of the above: the final image must look like a single real, professionally staged room, not a collage of separate product photos pasted together. Every piece of furniture must rest naturally and fully on the floor or be mounted the way that exact product is actually mounted in real life — never floating, never cut off, never overlapping another object incorrectly. Use one consistent light source, direction and color temperature for the whole scene, with matching shadows and reflections on every item, matching perspective and scale for every piece relative to the room and to each other, so the whole room reads as one coherent, cozy, believable photograph — not a set of furniture items placed next to each other.'
    ].filter(Boolean).join(' ');

    const images = [{ buffer: req.file.buffer, mimetype: req.file.mimetype }]
      .concat(userRef ? [userRef] : [])
      .concat(referenceParts);

    const { buffer: resultBuffer, mimeType, matched } = await generateChecked(fullPrompt + ' ' + buildStrictRules(referenceParts.length, palette) + ' ' + refNamesText, images, referenceParts, palette);
    if (matched) res.set('X-Matched-Items', matched.map(i => refOrigIndex[i]).join(','));
    res.set('X-Used-Items', refOrigIndex.join(','));

    const token = await getAccessToken();
    const resultFileId = await uploadImage(token, resultBuffer, 'result.jpg', mimeType);
    const furnitureList = await describeGeneratedFurniture(token, resultFileId);

    res.set('Content-Type', mimeType);
    res.set('X-Furniture-List', encodeURIComponent(JSON.stringify(furnitureList)));
    res.send(resultBuffer);
  } catch (err) {
    await releaseGeneration(reserved);
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.post('/classify-style', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) { res.status(400).json({ error: 'no image' }); return; }
    const token = await getAccessToken();
    const fileId = await uploadImage(token, req.file.buffer, 'target.jpg', req.file.mimetype);
    const styleKey = await classifyStyleKey(token, fileId);
    res.json({ styleKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.post('/generate-apartment', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'apartmentPhotos', maxCount: 7 }]), async (req, res) => {
  let reserved = null;
  try {
    const targetFile = req.files && req.files.image && req.files.image[0];
    const styleFiles = (req.files && req.files.apartmentPhotos) || [];
    if (!targetFile) { res.status(400).json({ error: 'no image' }); return; }
    if (!styleFiles.length) { res.status(400).json({ error: 'no apartment photos' }); return; }
    reserved = await reserveGeneration(req, res);
    if (!reserved) return;

    const room = req.body.room || '';
    const budgetPrompt = req.body.budgetPrompt || '';
    const userComment = (req.body.comment || '').trim();

    let referenceUrls = [];
    try { referenceUrls = JSON.parse(req.body.referenceImageUrls || '[]'); } catch (e) {}
    const { parts: referenceParts, origIndex: refOrigIndex } = await fetchReferenceParts(referenceUrls, 6);
    let refNames = [];
    try { refNames = JSON.parse(req.body.referenceNames || '[]'); } catch (e) {}
    const palette = '';
    const refNamesText = referenceParts.length ? 'The last ' + referenceParts.length + ' reference photos, in order, are these catalog products: ' + refOrigIndex.map((o, i) => (i + 1) + ') ' + String(refNames[o] || 'product').slice(0, 120) + mountHint(refNames[o])).join('; ') + '. Reproduce each of them as shown. Ceiling lights, chandeliers and pendant lamps always hang from the ceiling; wall-mounted items are always on the wall; never place them on the floor.' : '';
    const userRef = parseUserReference(req.body.userReferenceImage);

    const fullPrompt = [
      'The first image is a photo of a room that needs a new interior design: ' + (room || 'a room') + '.',
      referenceParts.length ? (userComment
        ? 'The last ' + referenceParts.length + ' image(s) in this request each show one specific real furniture or decor product from the Hoff catalog, matching the overall style. Use them for parts of the room that the user\'s request below does not already cover or ask to keep.'
        : 'This is the single most important instruction, follow it exactly: the last ' + referenceParts.length + ' image(s) in this request each show one specific real furniture or decor product from the Hoff catalog. Every main furniture piece in the redesigned room (every sofa, bed, wardrobe, table, chair, storage unit) MUST be exactly that product — same silhouette, same exact color, same exact material and finish as shown in its reference photo, not a similar or reinterpreted version and not a different color. Do not substitute any of them with a different-colored or different-shaped piece. Include every one of these reference items somewhere in the room — do not skip any of them. The requested color palette is MANDATORY for the whole room: walls, floor accents, textiles, decor AND furniture. Keep the shape and design of each reference product, but if its color clearly clashes with the requested palette, recolor that item to a matching palette color. Strictly avoid any saturated color that is not part of the palette.') : '',
      'The next ' + styleFiles.length + ' image(s) (before the Hoff product photos) show different rooms of the same apartment. Use them ONLY for the wall color or wallpaper, the flooring, the materials and the overall color palette of this home — reuse those exactly. Do NOT copy specific furniture pieces from these apartment photos, and do not let their mood override the exact furniture from the Hoff reference photos.',
      userRef ? 'One more image, placed right after the apartment photos and before the Hoff product photos, is a reference photo of a furniture or decor item supplied by the user, related to their request below. ' + USER_REFERENCE_RULES : '',
      userComment ? 'THE MOST IMPORTANT INSTRUCTION, follow it exactly and let it override anything above or below that conflicts with it: the user wrote this specific request: "' + userComment + '". If this request names or implies specific furniture or changes to keep, make, or avoid, follow it precisely. Only the items that this request explicitly asks to keep stay as they are in the original room photo. Every other piece of furniture from the original photo is removed and replaced by the catalog products from the reference photos.' : '',
      'At a ' + (budgetPrompt || 'mid-range') + ' furniture budget.',
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the first photo — only change the furniture, decor, materials and colors. Do not extend, widen or reveal any part of the room that is not visible in the original photo — if the photo shows only a corner or a partial view of the room, the result must show that exact same corner or partial view, with the exact same crop and framing, not a wider or different part of the room. Do not invent walls, windows, doors or floor area that are not already visible in the original photo.',
      'The final image must look like a single real, professionally staged room, not a collage of separate product photos pasted together. Every piece of furniture must rest naturally and fully on the floor or be mounted the way that exact product is actually mounted in real life — never floating, never cut off. Use one consistent light source, direction and color temperature for the whole scene, with matching shadows, perspective and scale, so the room reads as one coherent, believable photograph.',
      'Professional interior photography, photorealistic.'
    ].filter(Boolean).join(' ');

    const images = [{ buffer: targetFile.buffer, mimetype: targetFile.mimetype }]
      .concat(styleFiles.map(f => ({ buffer: f.buffer, mimetype: f.mimetype })))
      .concat(userRef ? [userRef] : [])
      .concat(referenceParts);

    const { buffer: resultBuffer, mimeType, matched } = await generateChecked(fullPrompt + ' ' + buildStrictRules(referenceParts.length, palette) + ' ' + refNamesText, images, referenceParts, palette);
    if (matched) res.set('X-Matched-Items', matched.map(i => refOrigIndex[i]).join(','));
    res.set('X-Used-Items', refOrigIndex.join(','));

    res.set('Content-Type', mimeType);
    res.send(resultBuffer);
  } catch (err) {
    await releaseGeneration(reserved);
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

const SUPPORT_SYSTEM_PROMPT_RU = 'Ты — дружелюбный ассистент поддержки сайта Room Factory. Room Factory — это сайт, где пользователь загружает фото своей комнаты, а ИИ создаёт варианты дизайна интерьера в выбранном стиле (скандинавский, минимализм, лофт, классика, japandi, бохо) за 30 секунд. ' +
  'Пользователь может выбрать тип комнаты, цветовую гамму, бюджет ремонта, магазин мебели (Hoff, Askona, Divan.ru) — после генерации сайт показывает похожую мебель из этого каталога. ' +
  'Есть тест на определение подходящего стиля (сравнение пар фото), и отдельный раздел «Стиль квартиры» (в боковом меню) — там можно загрузить фото комнаты для переделки плюс несколько фото других комнат квартиры, и ИИ подберёт дизайн, вписывающийся в общий стиль всей квартиры. ' +
  'Есть личный кабинет с историей сгенерированных дизайнов. Сейчас все основные функции сайта бесплатны. ' +
  'Отвечай кратко и дружелюбно, по-русски (если пользователь не написал на другом языке — тогда отвечай на его языке). Если вопрос не связан с сайтом Room Factory или ты не знаешь точного ответа — вежливо предложи написать на help@room-factory.ru. Не выдумывай факты о сервисе, которых нет в этом описании. Не давай юридических, налоговых или медицинских консультаций.';

app.post('/support-chat', express.json(), async (req, res) => {
  try {
    const message = (req.body && req.body.message || '').toString().slice(0, 2000);
    const history = Array.isArray(req.body && req.body.history) ? req.body.history.slice(-10) : [];
    if (!message) { res.status(400).json({ error: 'no message' }); return; }

    const token = await getAccessToken();
    const messages = [
      { role: 'system', content: SUPPORT_SYSTEM_PROMPT_RU },
      ...history.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string').map(m => ({ role: m.role, content: m.content.slice(0, 2000) })),
      { role: 'user', content: message }
    ];

    const resp = await fetch(API_BASE + '/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'GigaChat-2-Max', messages })
    });
    const text = await resp.text();
    if (!resp.ok) throw new Error('support-chat ' + resp.status + ': ' + text);
    const data = JSON.parse(text);
    const reply = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    res.json({ reply });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// ===================================================================
// Своя авторизация (замена Supabase Auth) + история (замена Supabase DB)
// ===================================================================

let dbSsl = { rejectUnauthorized: false };
(async () => {
  try {
    const resp = await fetch('https://st.timeweb.com/cloud-static/ca.crt');
    if (resp.ok) {
      const ca = await resp.text();
      if (ca.includes('BEGIN CERTIFICATE')) dbSsl = { ca, rejectUnauthorized: true };
    }
  } catch (e) { console.error('Не удалось скачать сертификат Timeweb, используем менее строгий SSL:', e.message); }
})();

const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT ? parseInt(process.env.PGPORT, 10) : 5432,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  ssl: process.env.PGHOST ? { rejectUnauthorized: false } : false
});

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const UNISENDER_API_KEY = process.env.UNISENDER_API_KEY;
const UNISENDER_SENDER_EMAIL = process.env.UNISENDER_SENDER_EMAIL;
// Unisender требует list_id в sendEmail, даже для одиночных писем вне рассылки.
// Получатель берётся из параметра email, в список он не добавляется и не виден
// в контактах — лимит бесплатного тарифа (100 контактов) это не расходует.
const UNISENDER_LIST_ID = process.env.UNISENDER_LIST_ID || '1';
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION === 'true';

async function sendMail(to, subject, text) {
  if (!UNISENDER_API_KEY || !UNISENDER_SENDER_EMAIL) {
    console.error('Почтовый сервис не настроен, письмо не отправлено:', to, subject);
    return;
  }
  const params = new URLSearchParams({
    format: 'json',
    api_key: UNISENDER_API_KEY,
    email: to,
    sender_name: 'Room Factory',
    sender_email: UNISENDER_SENDER_EMAIL,
    list_id: UNISENDER_LIST_ID,
    subject,
    body: text.replace(/\n/g, '<br>')
  });
  const resp = await fetch('https://api.unisender.com/ru/api/sendEmail', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  const data = await resp.json();
  if (!resp.ok || data.error) {
    throw new Error('Unisender API: ' + (data.error || resp.status));
  }
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 200;
}

function hasMailServer(email) {
  return new Promise((resolve) => {
    const domain = email.split('@')[1];
    if (!domain) { resolve(false); return; }
    dns.resolveMx(domain, (err, addresses) => {
      resolve(!err && addresses && addresses.length > 0);
    });
  });
}

function generateCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 дней
  await pool.query(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
    [hashToken(token), userId, expiresAt]
  );
  return token;
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) { res.status(401).json({ error: 'not_authenticated' }); return; }
    const { rows } = await pool.query(
      'SELECT s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()',
      [hashToken(token)]
    );
    if (!rows.length) { res.status(401).json({ error: 'not_authenticated' }); return; }
    req.user = { id: rows[0].user_id, email: rows[0].email };
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
}

app.post('/auth/register', authRateLimit('register', 10, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    if (!isValidEmail(email)) { res.status(400).json({ error: 'invalid_email' }); return; }
    if (password.length < 8) { res.status(400).json({ error: 'weak_password' }); return; }
    if (!(await hasMailServer(email))) { res.status(400).json({ error: 'invalid_email' }); return; }

    const existing = await pool.query('SELECT id, email_verified FROM users WHERE email = $1', [email]);
    if (existing.rows.length) { res.status(409).json({ error: 'email_taken' }); return; }

    const passwordHash = await bcrypt.hash(password, 10);
    const inserted = await pool.query(
      'INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, $3) RETURNING id',
      [email, passwordHash, !REQUIRE_EMAIL_VERIFICATION]
    );
    const userId = inserted.rows[0].id;

    if (!REQUIRE_EMAIL_VERIFICATION) {
      const token = await createSession(userId);
      res.json({ token, user: { id: userId, email, first_name: null, last_name: null, phone: null, preferred_style: null } });
      return;
    }

    const code = generateCode();
    await pool.query(
      'INSERT INTO email_verification_codes (user_id, code, expires_at) VALUES ($1, $2, now() + interval \'15 minutes\')',
      [userId, code]
    );
    await sendMail(email, 'Код подтверждения Room Factory', 'Ваш код подтверждения: ' + code + '\n\nОн действует 15 минут.');

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/verify-email', authRateLimit('verify-email', 10, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const code = (req.body.code || '').trim();
    const user = await pool.query('SELECT id, email_verified FROM users WHERE email = $1', [email]);
    if (!user.rows.length) { res.status(400).json({ error: 'invalid_code' }); return; }
    const userId = user.rows[0].id;

    const match = await pool.query(
      'SELECT id FROM email_verification_codes WHERE user_id = $1 AND code = $2 AND used = FALSE AND expires_at > now() ORDER BY created_at DESC LIMIT 1',
      [userId, code]
    );
    if (!match.rows.length) { res.status(400).json({ error: 'invalid_code' }); return; }

    await pool.query('UPDATE email_verification_codes SET used = TRUE WHERE id = $1', [match.rows[0].id]);
    await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [userId]);

    const token = await createSession(userId);
    res.json({ token, user: { id: userId, email, first_name: null, last_name: null, phone: null, preferred_style: null } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/resend-code', authRateLimit('resend-code', 5, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const user = await pool.query('SELECT id, email_verified FROM users WHERE email = $1', [email]);
    if (user.rows.length && !user.rows[0].email_verified) {
      const code = generateCode();
      await pool.query(
        'INSERT INTO email_verification_codes (user_id, code, expires_at) VALUES ($1, $2, now() + interval \'15 minutes\')',
        [user.rows[0].id, code]
      );
      await sendMail(email, 'Код подтверждения Room Factory', 'Ваш код подтверждения: ' + code + '\n\nОн действует 15 минут.');
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/login', authRateLimit('login', 15, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const user = await pool.query('SELECT id, password_hash, email_verified, first_name, last_name, phone, preferred_style FROM users WHERE email = $1', [email]);
    if (!user.rows.length) { res.status(401).json({ error: 'invalid_credentials' }); return; }

    const ok = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!ok) { res.status(401).json({ error: 'invalid_credentials' }); return; }
    if (REQUIRE_EMAIL_VERIFICATION && !user.rows[0].email_verified) { res.status(403).json({ error: 'email_not_verified' }); return; }

    const token = await createSession(user.rows[0].id);
    res.json({ token, user: {
      id: user.rows[0].id,
      email,
      first_name: user.rows[0].first_name,
      last_name: user.rows[0].last_name,
      phone: user.rows[0].phone,
      preferred_style: user.rows[0].preferred_style
    } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/logout', requireAuth, express.json(), async (req, res) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(token)]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, first_name, last_name, phone, preferred_style FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length) { res.status(401).json({ error: 'not_authenticated' }); return; }
    res.json({ user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/auth/me', requireAuth, express.json(), async (req, res) => {
  try {
    const firstName = typeof req.body.first_name === 'string' ? req.body.first_name.slice(0, 100) : undefined;
    const lastName = typeof req.body.last_name === 'string' ? req.body.last_name.slice(0, 100) : undefined;
    const phone = typeof req.body.phone === 'string' ? req.body.phone.slice(0, 30) : undefined;
    const preferredStyle = typeof req.body.preferred_style === 'string' ? req.body.preferred_style.slice(0, 50) : undefined;

    const { rows } = await pool.query(
      `UPDATE users SET
         first_name = COALESCE($1, first_name),
         last_name = COALESCE($2, last_name),
         phone = COALESCE($3, phone),
         preferred_style = COALESCE($4, preferred_style)
       WHERE id = $5
       RETURNING id, email, first_name, last_name, phone, preferred_style`,
      [firstName, lastName, phone, preferredStyle, req.user.id]
    );
    res.json({ user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/request-password-reset', authRateLimit('request-password-reset', 5, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (user.rows.length) {
      const code = generateCode();
      await pool.query(
        'INSERT INTO password_reset_codes (user_id, code, expires_at) VALUES ($1, $2, now() + interval \'15 minutes\')',
        [user.rows[0].id, code]
      );
      await sendMail(email, 'Восстановление пароля Room Factory', 'Код для сброса пароля: ' + code + '\n\nОн действует 15 минут. Если это были не вы — просто проигнорируйте письмо.');
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/reset-password', authRateLimit('reset-password', 10, 15 * 60 * 1000), express.json(), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const code = (req.body.code || '').trim();
    const newPassword = req.body.newPassword || '';
    if (newPassword.length < 8) { res.status(400).json({ error: 'weak_password' }); return; }

    const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (!user.rows.length) { res.status(400).json({ error: 'invalid_code' }); return; }
    const userId = user.rows[0].id;

    const match = await pool.query(
      'SELECT id FROM password_reset_codes WHERE user_id = $1 AND code = $2 AND used = FALSE AND expires_at > now() ORDER BY created_at DESC LIMIT 1',
      [userId, code]
    );
    if (!match.rows.length) { res.status(400).json({ error: 'invalid_code' }); return; }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE password_reset_codes SET used = TRUE WHERE id = $1', [match.rows[0].id]);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]); // разлогиниваем везде из соображений безопасности

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===================================================================
// История генераций
// ===================================================================

async function uploadToSupabaseStorage(userId, buffer, mimetype) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase Storage не настроен на сервере');
  const ext = mimetype === 'image/png' ? 'png' : 'jpg';
  const path = userId + '/' + Date.now() + '.' + ext;
  const resp = await fetch(SUPABASE_URL + '/storage/v1/object/designs/' + path, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY,
      'apikey': SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type': mimetype || 'image/jpeg'
    },
    body: buffer
  });
  if (!resp.ok) throw new Error('storage upload ' + resp.status + ': ' + (await resp.text()));
  return SUPABASE_URL + '/storage/v1/object/public/designs/' + path;
}

app.get('/generations', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, image_url, style_key, style_label, room_label, store_label, furniture, created_at FROM generations WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ generations: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/generations', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) { res.status(400).json({ error: 'no image' }); return; }
    const imageUrl = await uploadToSupabaseStorage(req.user.id, req.file.buffer, req.file.mimetype);
    // Список использованной мебели (название/фото/цена/ссылка) — чтобы при открытии
    // сохранённого дизайна показать его целиком, с мебелью под фото. Присылается
    // клиентом как JSON-строка; если она некорректная или слишком длинная — просто
    // не сохраняем мебель, сам дизайн при этом всё равно сохраняется.
    let furniture = null;
    if (typeof req.body.furniture === 'string' && req.body.furniture.length <= 20000) {
      try {
        const parsed = JSON.parse(req.body.furniture);
        if (Array.isArray(parsed)) {
          furniture = parsed.slice(0, 12).map(p => ({
            name: typeof p.name === 'string' ? p.name.slice(0, 200) : '',
            img: typeof p.img === 'string' ? p.img.slice(0, 500) : '',
            price: typeof p.price === 'string' ? p.price.slice(0, 50) : '',
            url: typeof p.url === 'string' ? p.url.slice(0, 500) : ''
          }));
        }
      } catch (e) { /* игнорируем некорректный JSON мебели, дизайн всё равно сохраняем */ }
    }
    const { rows } = await pool.query(
      'INSERT INTO generations (user_id, image_url, style_key, style_label, room_label, store_label, furniture) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, image_url, style_key, style_label, room_label, store_label, furniture, created_at',
      [req.user.id, imageUrl, req.body.styleKey || null, req.body.styleLabel || null, req.body.roomLabel || null, req.body.storeLabel || null, furniture ? JSON.stringify(furniture) : null]
    );
    res.json({ generation: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/generations/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM generations WHERE id = $1 AND user_id = $2 RETURNING image_url',
      [req.params.id, req.user.id]
    );
    if (!rows.length) { res.status(404).json({ error: 'not_found' }); return; }

    if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
      try {
        const marker = '/designs/';
        const idx = rows[0].image_url.indexOf(marker);
        if (idx !== -1) {
          const path = rows[0].image_url.slice(idx + marker.length);
          await fetch(SUPABASE_URL + '/storage/v1/object/designs/' + path, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY, 'apikey': SUPABASE_SERVICE_ROLE_KEY }
          });
        }
      } catch (e2) { console.error('Не удалось удалить файл из хранилища:', e2); }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/', (req, res) => res.send('Room Factory GigaChat + Gemini proxy is running'));

// Письмо-напоминание тем, кто зарегистрировался и подтвердил почту, но ни разу
// не пробовал сервис. Уходит один раз, примерно через REENGAGEMENT_DAYS дней после
// регистрации. Нужны колонки users.created_at и users.reengagement_sent_at —
// см. инструкцию для добавления через Adminer. Если колонок нет, функция просто
// упадёт с ошибкой в лог при каждой проверке и ничего не отправит — на остальную
// работу сайта это не влияет.
const REENGAGEMENT_DAYS = parseInt(process.env.REENGAGEMENT_DAYS || '7', 10);
async function sendReengagementEmails() {
  try {
    const { rows } = await pool.query(
      `SELECT id, email FROM users
       WHERE email_verified = TRUE
         AND generations_used = 0
         AND reengagement_sent_at IS NULL
         AND created_at <= now() - ($1 || ' days')::interval
         AND created_at > now() - ($1 || ' days')::interval - interval '1 day'`,
      [String(REENGAGEMENT_DAYS)]
    );
    for (const u of rows) {
      try {
        await sendMail(
          u.email,
          'Попробуйте создать дизайн за 30 секунд',
          'Здравствуйте!\n\n' +
          'Вы зарегистрировались на Room Factory, но ещё не пробовали создать дизайн комнаты.\n\n' +
          'Загрузите одно фото своей комнаты — и за 30 секунд получите готовый вариант интерьера с подбором мебели из каталога: https://room-factory.ru\n\n' +
          'Если вы уже израсходовали бесплатные генерации или это письмо вам не актуально, можно просто его не замечать.'
        );
        await pool.query('UPDATE users SET reengagement_sent_at = now() WHERE id = $1', [u.id]);
      } catch (e) {
        console.error('Не удалось отправить письмо-напоминание:', u.email, e);
      }
    }
  } catch (e) {
    console.error('Ошибка выборки пользователей для письма-напоминания (проверьте колонки users.created_at / users.reengagement_sent_at):', e);
  }
}
setInterval(sendReengagementEmails, 60 * 60 * 1000).unref();
sendReengagementEmails();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('listening on port ' + PORT));
