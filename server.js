const express = require('express');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Expose-Headers', 'X-Furniture-List');
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
          '2) Точное число окон цифрой (например: "Окон: 1") и на какой именно стене каждое расположено (левая от камеры, правая от камеры, дальняя стена напротив камеры, стена за спиной снимающего), примерная ширина и высота окон относительно высоты потолка, на каком расстоянии от пола. Считай внимательно — не путай одно широкое окно с двумя окнами. ' +
          '3) Где находится дверь или дверной проём — на какой стене, ближе к какому углу, на каком примерно расстоянии от этого угла (в долях ширины стены: близко к углу, посередине, и т.д.), открывается внутрь или наружу, есть ли ещё дверные проёмы (в другие комнаты, шкафы). ВАЖНО: если дверь или дверной проём не попадают в кадр (например, находятся за спиной снимающего) — так и напиши: "дверь не видна в кадре". Не выдумывай дверь, если её не видно на фото. ' +
          '4) Высота потолков на глаз в метрах примерно. ' +
          '5) Ракурс и точка съёмки — из какой точки комнаты снято фото, в каком направлении смотрит камера, какая часть комнаты попадает в кадр, а какая нет. ' +
          '6) Цвет и материал стен, пола и потолка на фото. ' +
          '7) Какие ещё архитектурные элементы есть (ниши, колонны, балки, встроенные шкафы, батареи отопления, розетки и выключатели если видно). ' +
          '8) Общее впечатление о размере помещения: комната выглядит просторной/большой или небольшой/компактной (оцени по пропорциям, а не только по кадру). ' +
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
  const furnitureBits = [];
  if (roomFurnitureRu[meta.roomLabel]) furnitureBits.push(roomFurnitureRu[meta.roomLabel]);
  if (meta.extraFurniture) furnitureBits.push(meta.extraFurniture);
  const requiredFurniture = furnitureBits.join(', ');
  const styleDetails = styleDetailsRu[meta.styleLabel];

  const geoParts = [];
  if (meta.roomShape) geoParts.push('форма помещения — ' + meta.roomShape.toLowerCase());
  if (meta.roomArea) geoParts.push('площадь примерно ' + meta.roomArea + ' м²');
  if (meta.windowCount !== undefined && meta.windowCount !== '') geoParts.push('точное количество окон — ' + meta.windowCount + (Number(meta.windowCount) === 0 ? ' (окон нет вообще, не рисуй ни одного окна)' : ''));
  const geoNote = geoParts.join(', ');

  const leadParts = ['Нарисуй фотореалистичный интерьер'];
  if (meta.roomLabel) leadParts.push('— ' + meta.roomLabel.toLowerCase());
  if (meta.styleLabel) leadParts.push('в стиле «' + meta.styleLabel + '»');
  if (requiredFurniture) leadParts.push('ОБЯЗАТЕЛЬНАЯ МЕБЕЛЬ (без неё результат неверный): ' + requiredFurniture);
  if (meta.colorLabel) leadParts.push('ЦВЕТОВАЯ ГАММА (обязательна к соблюдению на стенах, полу, крупной мебели): ' + meta.colorLabel);
  if (geoNote) leadParts.push('ТОЧНЫЕ ДАННЫЕ О КОМНАТЕ ОТ ПОЛЬЗОВАТЕЛЯ (используй вместо своей оценки по фото): ' + geoNote);
  const lead = leadParts.join(', ') + '.';

  const fullPrompt = [
    lead,
    geoNote ? 'Повторяю про геометрию комнаты: пользователь лично указал следующие точные данные — ' + geoNote + '. Это достовернее, чем твоя собственная оценка по фото, — используй именно эти данные, а не своё впечатление от снимка, если они расходятся.' : '',
    requiredFurniture ? 'Повторяю про мебель: в комнате обязательно должна присутствовать вся следующая мебель: ' + requiredFurniture + '. Это не пожелание, а обязательное требование — расставь её как в реальной обставленной комнате, а не одним случайным предметом посередине, и не заменяй ни один из этих предметов на другой (например, если нужна кровать — рисуй именно кровать, а не диван или кресло).' : '',
    meta.colorLabel ? 'Повторяю: цветовая гамма — ' + meta.colorLabel + '. Это условие важнее типичных материалов и цветов для этого стиля — даже если для стиля обычно характерны другие оттенки (например, бетон для минимализма или тёмные тона для лофта), стены, пол и мебель всё равно должны быть перекрашены в указанную гамму, а фактуру и форму сохрани стилевую.' : '',
    styleDetails ? 'Что означает стиль «' + meta.styleLabel + '»: ' + styleDetails + '.' : '',
    'Дополнительные пожелания по стилю и мебели: ' + stylePrompt + '.',
    'Планировка помещения (строго обязательно к соблюдению): сохрани такую же форму, пропорции и общий размер комнаты (если она большая и просторная — не превращай в маленькую, и наоборот), высоту потолков, такой же ракурс и точку обзора камеры, и такое же количество и расположение окон и дверей, как описано ниже' + (geoNote ? ' (но форму, площадь и число окон бери из точных данных пользователя выше, если они отличаются от твоего впечатления по фото)' : '') + ': ' + description,
    'КРИТИЧЕСКИ ВАЖНО про окна и двери: нарисуй ' + (meta.windowCount !== undefined && meta.windowCount !== '' ? 'ровно ' + meta.windowCount + ' окон(а) — именно столько, сколько указал пользователь' : 'ровно столько окон, сколько указано в описании выше') + ' — ни одним больше. Если окно одно, в результате должно быть только одно окно, не два и не три. То же самое для дверей: если сказано, что дверь не видна в кадре или отсутствует, НЕ рисуй дверь вообще — в этом месте должна быть просто сплошная стена, без двери и дверного проёма. Строго запрещено добавлять любые окна, двери, стены, ниши или архитектурные элементы, которых нет в описании или в данных пользователя.',
    'Не добавляй в кадр животных, людей, посторонние предметы или декор, не относящийся к интерьеру комнаты.',
    (meta.colorLabel || requiredFurniture || geoNote)
      ? 'Ещё раз главные условия, самые важные: ' + [geoNote ? 'геометрия комнаты — ' + geoNote : '', requiredFurniture ? 'обязательно вся мебель: ' + requiredFurniture : '', meta.colorLabel ? 'цветовая гамма — ' + meta.colorLabel : ''].filter(Boolean).join('; ') + '.'
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
    const roomShape = req.body.roomShape || '';
    const roomArea = req.body.roomArea || '';
    const windowCount = req.body.windowCount || '';
    const extraFurniture = req.body.extraFurniture || '';
    const stylePrompt = [prompt, comment].filter(Boolean).join(', ');

    const token = await getAccessToken();
    const fileId = await uploadImage(token, req.file.buffer, req.file.originalname, req.file.mimetype);
    const description = await describeImage(token, fileId);
    const resultFileId = await generateImage(token, description, stylePrompt, { roomLabel, colorLabel, styleLabel, roomShape, roomArea, windowCount, extraFurniture });
    const [imageBuffer, furnitureList] = await Promise.all([
      downloadImage(token, resultFileId),
      describeGeneratedFurniture(token, resultFileId)
    ]);

    res.set('Content-Type', 'image/jpeg');
    res.set('X-Furniture-List', encodeURIComponent(JSON.stringify(furnitureList)));
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

const SUPPORT_SYSTEM_PROMPT_RU = 'Ты — дружелюбный ассистент поддержки сайта Room Factory. Room Factory — это сайт, где пользователь загружает фото своей комнаты, а ИИ создаёт варианты дизайна интерьера в выбранном стиле (скандинавский, минимализм, лофт, классика, japandi, бохо) за 30 секунд. ' +
  'Пользователь может выбрать тип комнаты, цветовую гамму, бюджет ремонта, магазин мебели (Hoff, Askona, Divan.ru) — после генерации сайт показывает похожую мебель из этого каталога. Есть необязательные поля: форма и площадь комнаты, число окон — их можно указать вручную, чтобы результат точнее совпадал с реальной планировкой. ' +
  'Есть личный кабинет с историей сгенерированных дизайнов, тест на определение стиля, и отдельный режим "3D-тур" — по размерам комнат строится 3D-модель квартиры, по которой можно пройтись. Сейчас все основные функции сайта бесплатны. ' +
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

app.get('/', (req, res) => res.send('Room Factory GigaChat proxy is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('listening on port ' + PORT));
