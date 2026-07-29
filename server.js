const express = require('express');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') { res.sendStatus(200); return; }
  next();
});

const OAUTH_URL = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth';
const API_BASE = 'https://gigachat.devices.sberbank.ru/api/v1';
const AUTH_KEY = process.env.GIGACHAT_AUTH_KEY;

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
async function describeImage(token, fileId) {
  const resp = await fetch(API_BASE + '/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'GigaChat-2-Max',
      messages: [{
        role: 'user',
        content: 'Подробно опиши планировку комнаты на прикреплённом фото для дизайнера интерьера: сколько окон и на какой стене они расположены, где находятся двери, примерная форма и пропорции помещения, тип комнаты. Только фактическое описание расположения объектов.',
        attachments: [fileId]
      }]
    })
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('describe ' + resp.status + ': ' + text);
  const data = JSON.parse(text);
  const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!content || typeof content !== 'string') throw new Error('no description: ' + text);
  return content;
}


async function generateImage(token, description, stylePrompt) {
  const fullPrompt = 'Нарисуй фотореалистичный интерьер комнаты в этом стиле: ' + stylePrompt + '. Планировка комнаты, обязательно сохрани точное расположение окон, дверей и форму помещения как описано здесь: ' + description;
  const resp = await fetch(API_BASE + '/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'GigaChat-2-Max',
      messages: [{ role: 'user', content: fullPrompt }],
      function_call: 'auto'
    })
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('generate ' + resp.status + ': ' + text);
  const data = JSON.parse(text);
  const content = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
  const match = content.match(/img[^>]*src="([^"]+)"/) || content.match(/([0-9a-f-]{20,})/i);
  if (!match) throw new Error('no image in response: ' + content);
  return match[1];
}

async function downloadImage(token, fileId) {
  const resp = await fetch(API_BASE + '/files/' + fileId + '/content', {
    method: 'GET',
    headers: { 'Authorization': 'Bearer ' + token }
  });
  if (!resp.ok) throw new Error('download ' + resp.status);
  const ab = await resp.arrayBuffer();
  return Buffer.from(ab);
}

app.post('/generate', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) { res.status(400).json({ error: 'no image' }); return; }
    const prompt = req.body.prompt || '';
    const comment = req.body.comment || '';
    const stylePrompt = [prompt, comment].filter(Boolean).join(', ');

    const token = await getAccessToken();
    const fileId = await uploadImage(token, req.file.buffer, req.file.originalname, req.file.mimetype);
    const description = await describeImage(token, fileId);
    const resultFileId = await generateImage(token, description, stylePrompt);
    const imageBuffer = await downloadImage(token, resultFileId);

    res.set('Content-Type', 'image/jpeg');
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.get('/', (req, res) => res.send('Room Factory GigaChat proxy is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('listening on port ' + PORT));
