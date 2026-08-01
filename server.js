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
        content: 'Ты помогаешь дизайнеру интерьера составить техническое задание на 3D-визуализацию. Очень подробно и по пунктам опиши планировку комнаты на прикреплённом фото, как для человека, который эту комнату никогда не видел и должен нарисовать её с нуля: ' +
          '1) Тип и форма помещения (квадратная, прямоугольная, вытянутая, Г-образная), примерное соотношение ширины и длины (например, "примерно 1 к 1.5"). ' +
          '2) Сколько окон, на какой именно стене каждое расположено (левая от камеры, правая от камеры, дальняя стена напротив камеры, стена за спиной снимающего), примерная ширина и высота окон относительно высоты потолка, на каком расстоянии от пола. ' +
          '3) Где находится дверь или дверной проём — на какой стене, ближе к какому углу, открывается внутрь или наружу, есть ли ещё дверные проёмы (в другие комнаты, шкафы). ' +
          '4) Высота потолков на глаз в метрах примерно. ' +
          '5) Ракурс и точка съёмки — из какой точки комнаты снято фото, в каком направлении смотрит камера, какая часть комнаты попадает в кадр, а какая нет. ' +
          '6) Цвет и материал стен, пола и потолка на фото. ' +
          '7) Какие ещё архитектурные элементы есть (ниши, колонны, балки, встроенные шкафы, батареи отопления, розетки и выключатели если видно). ' +
          'Пиши только фактическое, максимально конкретное описание расположения объектов — числа, стороны, пропорции. Не описывай мебель, декор и не давай оценок вкуса.',
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

const roomFurnitureRu = {
  'Гостиная': 'диван, журнальный столик, место для хранения (стеллаж, тумба или комод)',
  'Спальня': 'двуспальная кровать с изголовьем и постельным бельём (это обязательный центральный предмет мебели), прикроватные тумбы по бокам от кровати',
  'Кухня': 'кухонный гарнитур с фасадами и техникой, обеденный стол со стульями',
  'Ванная': 'раковина с тумбой, зеркало, сантехника ванной комнаты (ванна или душевая кабина)',
  'Детская': 'детская кровать, стол для занятий со стулом, полки или ящики для игрушек',
  'Кабинет': 'письменный стол, рабочее кресло, стеллаж или полки для книг',
  'Прихожая': 'вешалка или шкаф для одежды, обувница, зеркало',
  'Столовая': 'обеденный стол и стулья по числу мест, буфет или сервант'
};

const styleDetailsRu = {
  'Скандинавский': 'светлое натуральное дерево, простые лаконичные формы мебели без вычурности, много естественного света, минимум декора',
  'Минимализм': 'предельно простые прямые формы без резьбы, орнаментов и декоративных деталей; свободное незагромождённое пространство; никаких округлых игрушечных или "милых" форм мебели; спокойная сдержанная композиция',
  'Лофт': 'брутальные лаконичные формы мебели, индустриальные детали (металл, кирпичная текстура), высокие потолки',
  'Классика': 'симметричная композиция, дорогие благородные материалы, изящные резные детали мебели',
  'Japandi': 'низкая мебель, природные текстуры, спокойная сдержанная композиция без ярких контрастов',
  'Бохо': 'эклектичное сочетание текстур и узоров, растения, тёплый уютный беспорядок'
};

async function generateImage(token, description, stylePrompt, meta) {
  meta = meta || {};
  const requiredFurniture = roomFurnitureRu[meta.roomLabel];
  const styleDetails = styleDetailsRu[meta.styleLabel];
  const fullPrompt = [
    'Нарисуй фотореалистичный интерьер комнаты.',
    meta.roomLabel ? 'Тип помещения: строго ' + meta.roomLabel + '. Результат обязательно должен выглядеть именно как ' + meta.roomLabel.toLowerCase() + ' — это самое важное условие.' : '',
    requiredFurniture ? 'В комнате обязательно должна присутствовать мебель, характерная именно для этого типа помещения: ' + requiredFurniture + '. Расставь её как в реальной обставленной комнате, а не одним случайным предметом посередине.' : '',
    meta.styleLabel ? 'Стиль интерьера: строго ' + meta.styleLabel + '.' + (styleDetails ? ' Это означает: ' + styleDetails + '.' : '') : '',
    meta.colorLabel ? 'Основная цветовая гамма: строго ' + meta.colorLabel + '. ВАЖНО: цвет стен, пола и мебели должен соответствовать именно этой гамме — даже если для выбранного стиля обычно характерны другие материалы или оттенки (например, бетон для минимализма или тёмные тона для лофта), перекрась эти поверхности в выбранную гамму, сохранив при этом фактуру и форму, характерную для стиля. Цветовая гамма важнее типичных цветов стиля.' : '',
    'Дополнительные пожелания по стилю и мебели: ' + stylePrompt + '.',
    'Планировка помещения (строго обязательно к соблюдению): сохрани точно такую же форму и пропорции комнаты, высоту потолков, такой же ракурс и точку обзора камеры, и такое же количество и расположение окон и дверей, как описано ниже. Не добавляй новые окна, двери или стены и не меняй их положение и размер: ' + description,
    'Не добавляй в кадр животных, людей, посторонние предметы или декор, не относящийся к интерьеру комнаты.',
    (meta.roomLabel || meta.colorLabel)
      ? 'Ещё раз главное условие: это ' + (meta.roomLabel ? meta.roomLabel.toLowerCase() : 'комната') + (meta.colorLabel ? ' в цветовой гамме "' + meta.colorLabel + '"' : '') + (meta.styleLabel ? ' в стиле "' + meta.styleLabel + '"' : '') + (requiredFurniture ? ', с реальной обстановкой (' + requiredFurniture + ')' : '') + '.'
      : ''
  ].filter(Boolean).join(' ');

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
    const roomLabel = req.body.roomLabel || '';
    const colorLabel = req.body.colorLabel || '';
    const styleLabel = req.body.styleLabel || '';
    const stylePrompt = [prompt, comment].filter(Boolean).join(', ');

    const token = await getAccessToken();
    const fileId = await uploadImage(token, req.file.buffer, req.file.originalname, req.file.mimetype);
    const description = await describeImage(token, fileId);
    const resultFileId = await generateImage(token, description, stylePrompt, { roomLabel, colorLabel, styleLabel });
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
