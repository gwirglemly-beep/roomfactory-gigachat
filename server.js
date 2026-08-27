const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { GoogleGenAI } = require('@google/genai');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Expose-Headers', 'X-Furniture-List, X-Style-Key');
  if (req.method === 'OPTIONS') { res.sendStatus(200); return; }
  next();
});

const OAUTH_URL = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth';
const API_BASE = 'https://gigachat.devices.sberbank.ru/api/v1';
const AUTH_KEY = process.env.GIGACHAT_AUTH_KEY;

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-3.1-flash-image';

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

async function generateWithGemini(promptText, images) {
  const client = getGeminiClient();
  const parts = [{ text: promptText }];
  images.forEach(img => {
    parts.push({ inlineData: { mimeType: img.mimetype || 'image/jpeg', data: img.buffer.toString('base64') } });
  });
  const response = await client.models.generateContent({
    model: GEMINI_MODEL,
    contents: [{ role: 'user', parts }]
  });
  const part = findGeminiImagePart(response);
  if (!part) throw new Error('no image in gemini response: ' + JSON.stringify(response).slice(0, 800));
  return { buffer: Buffer.from(part.data, 'base64'), mimeType: part.mimeType || 'image/jpeg' };
}

async function fetchImageAsPart(url) {
  try {
    const resp = await fetch(url);
    if (!resp.ok) return null;
    const mimetype = resp.headers.get('content-type') || 'image/jpeg';
    const buffer = Buffer.from(await resp.arrayBuffer());
    return { buffer, mimetype };
  } catch (e) {
    return null;
  }
}

app.post('/generate', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) { res.status(400).json({ error: 'no image' }); return; }
    const prompt = req.body.prompt || '';

    let referenceUrls = [];
    try { referenceUrls = JSON.parse(req.body.referenceImageUrls || '[]'); } catch (e) {}
    const referenceParts = (await Promise.all((Array.isArray(referenceUrls) ? referenceUrls : []).slice(0, 3).map(fetchImageAsPart))).filter(Boolean);

    const fullPrompt = [
      'Redesign this exact room photo: ' + prompt + '.',
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the original photo — only change the furniture, decor, materials and colors.',
      referenceParts.length ? 'The additional reference photos show real furniture products that must appear in the redesigned room, matching their exact appearance (shape, material, color) as closely as possible.' : ''
    ].filter(Boolean).join(' ');

    const { buffer: resultBuffer, mimeType } = await generateWithGemini(fullPrompt, [{ buffer: req.file.buffer, mimetype: req.file.mimetype }, ...referenceParts]);

    const token = await getAccessToken();
    const resultFileId = await uploadImage(token, resultBuffer, 'result.jpg', mimeType);
    const furnitureList = await describeGeneratedFurniture(token, resultFileId);

    res.set('Content-Type', mimeType);
    res.set('X-Furniture-List', encodeURIComponent(JSON.stringify(furnitureList)));
    res.send(resultBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.post('/generate-apartment', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'apartmentPhotos', maxCount: 7 }]), async (req, res) => {
  try {
    const targetFile = req.files && req.files.image && req.files.image[0];
    const styleFiles = (req.files && req.files.apartmentPhotos) || [];
    if (!targetFile) { res.status(400).json({ error: 'no image' }); return; }
    if (!styleFiles.length) { res.status(400).json({ error: 'no apartment photos' }); return; }

    const room = req.body.room || '';
    const color = req.body.color || '';
    const budgetPrompt = req.body.budgetPrompt || '';
    const comment = req.body.comment || '';

    const fullPrompt = [
      'The first image is a photo of a room that needs a new interior design: ' + (room || 'a room') + '.',
      'The other images show different rooms of the same apartment — use them only as a reference for the overall interior style, materials and color mood already present in this home.',
      'Redesign the first room to match that same style, using colors: ' + (color || 'a coordinated palette') + ', at a ' + (budgetPrompt || 'mid-range') + ' furniture budget.',
      comment,
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the first photo — only change the furniture, decor, materials and colors.',
      'Professional interior photography, photorealistic.'
    ].filter(Boolean).join(' ');

    const images = [{ buffer: targetFile.buffer, mimetype: targetFile.mimetype }]
      .concat(styleFiles.map(f => ({ buffer: f.buffer, mimetype: f.mimetype })));

    const { buffer: resultBuffer, mimeType } = await generateWithGemini(fullPrompt, images);

    const token = await getAccessToken();
    const resultFileId = await uploadImage(token, resultBuffer, 'result.jpg', mimeType);
    const [furnitureList, styleKey] = await Promise.all([
      describeGeneratedFurniture(token, resultFileId),
      classifyStyleKey(token, resultFileId)
    ]);

    res.set('Content-Type', mimeType);
    res.set('X-Furniture-List', encodeURIComponent(JSON.stringify(furnitureList)));
    res.set('X-Style-Key', styleKey);
    res.send(resultBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

const SUPPORT_SYSTEM_PROMPT_RU = 'Ты — дружелюбный ассистент поддержки сайта Room Factory. Room Factory — это сайт, где пользователь загружает фото своей комнаты, а ИИ создаёт варианты дизайна интерьера в выбранном стиле (скандинавский, минимализм, лофт, классика, japandi, бохо) за 30 секунд. ' +
  'Пользователь может выбрать тип комнаты, цветовую гамму, бюджет ремонта, магазин мебели (Hoff, Askona, Divan.ru) — после генерации сайт показывает похожую мебель из этого каталога. ' +
  'Есть тест на определение подходящего стиля (сравнение пар фото), и отдельный раздел «Стиль квартиры» (в боковом меню) — там можно загрузить фото комнаты для переделки плюс несколько фото других комнат квартиры, и ИИ подберёт дизайн, вписывающийся в общий стиль всей квартиры. ' +
  'Есть личный кабинет с историей сгенерированных дизайнов. Сейчас все основные функции сайта бесплатны. ' +
  'Отвечай кратко и дружелюбно, по-русски (если пользователь не написал на другом языке — тогда отвечай на его языке). Если вопрос не связан с сайтом Room Factory или ты не знаешь точного ответа — вежливо предложи написать на roomfactory_help@mail.ru. Не выдумывай факты о сервисе, которых нет в этом описании. Не давай юридических, налоговых или медицинских консультаций.';

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

app.get('/', (req, res) => res.send('Room Factory GigaChat + Gemini proxy is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('listening on port ' + PORT));
