// Отдельный маленький сервис — остаётся на Render (или другом зарубежном хостинге),
// потому что Gemini может не принимать запросы с российских IP. Это единственная
// часть системы, которая обращается к Google. Сюда попадают ТОЛЬКО уже обезличенные
// данные: фото без EXIF, без людей/документов (проверено на основном сервере до
// отправки сюда), текстовый промпт и публичные ссылки на фото мебели из каталога.
// Никакие email, ID пользователя, IP или токены сессии сюда не передаются и не
// пересылаются в Gemini — так же, как было устроено раньше в едином server.js.
const express = require('express');
const dns = require('dns');
const { GoogleGenAI } = require('@google/genai');

dns.setDefaultResultOrder('ipv4first');

const app = express();
app.use(express.json({ limit: '40mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Общий секрет между основным сервером (Timeweb) и этим relay — чтобы его не мог
// дёргать никто посторонний, кто узнает адрес. Задаётся переменной окружения
// RELAY_SHARED_SECRET одинаково на Timeweb и на Render.
const RELAY_SHARED_SECRET = process.env.RELAY_SHARED_SECRET;
function requireSharedSecret(req, res, next) {
  if (!RELAY_SHARED_SECRET || req.get('X-Relay-Secret') !== RELAY_SHARED_SECRET) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
}

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-3.1-flash-image';

let geminiClient = null;
function getGeminiClient() {
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY is not set on the relay');
  if (!geminiClient) geminiClient = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  return geminiClient;
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

// Та же бело-список хостов, что был на основном сервере — фото мебели только с этого CDN.
const ALLOWED_IMAGE_HOSTS = ['avatars.mds.yandex.net', 'static.tildacdn.com'];

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

async function fetchReferenceParts(referenceUrls, limit) {
  const urls = (Array.isArray(referenceUrls) ? referenceUrls : []).slice(0, limit);
  const results = await Promise.all(urls.map(fetchImageAsPart));
  const parts = results.filter(Boolean);
  const origIndex = results.map((p, i) => (p ? i : -1)).filter(i => i >= 0);
  return { parts, origIndex };
}

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

// Подсказка про способ установки: потолочные светильники вешаем на потолок, настенные вещи — на стену, а не ставим на пол.
function mountHint(name) {
  const n = String(name || '').toLowerCase();
  if (/люстр|потолоч|подвесн|накладн/.test(n)) return ' (ceiling-mounted: it MUST hang from the ceiling, never stand on the floor or furniture)';
  if (/(^|\s)бра(\s|$)|настенн|навесн|вешалк|полка/.test(n)) return ' (wall-mounted: it MUST be fixed on the wall)';
  if (/торшер|напольн/.test(n)) return ' (floor lamp: stands on the floor)';
  if (/зеркал/.test(n)) return ' (mirror: hang it on the wall or lean it against the wall)';
  return '';
}

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

// Проверка загруженного фото перед генерацией: это должна быть пустая или обставленная комната,
// без людей и частей тела в кадре, без документов, экранов с личными данными и именных табличек/дипломов.
// Если проверка сама не удалась (сбой модели) — пропускаем фото (fail-open), чтобы не блокировать пользователей зря.
async function checkRoomPhoto(buffer, mimetype) {
  const client = getGeminiClient();
  const parts = [
    { text: 'You are a content and privacy filter for an interior-design app. The image must be a photo of an empty or furnished room interior (walls, floor, furniture) suitable for redesign, with nothing in it that could identify a real person. ' +
      'Reject it if ANY of these appear in the room: ' +
      '(1) a real person or a visible human body part (face, hand, arm, leg, etc.); ' +
      '(2) a document with legible text (passport, ID, certificate, contract, utility bill, letter); ' +
      '(3) a screen (phone, computer, TV) showing legible personal content such as messages, photos of people or an account/profile; ' +
      '(4) a personal photograph or portrait of a real person (a family photo, a selfie print, a portrait print) displayed in a frame, on a shelf or on a table — this is different from generic wall art/posters/paintings/abstract or stock photography, which are normal decor and are allowed; ' +
      '(5) a nameplate, personalized diploma, certificate, award or badge showing a real person\'s name; ' +
      '(6) the image is clearly not a room/interior photo at all (e.g. a random object close-up, an outdoor scene, an animal). ' +
      'Answer with ONLY a JSON object: {"ok": true or false, "reason": "short reason in Russian, under 90 characters, explaining to the user what to fix, empty string if ok is true"}.' },
    { inlineData: { mimeType: mimetype || 'image/jpeg', data: buffer.toString('base64') } }
  ];
  for (const model of verifyModelOrder()) {
    try {
      const response = await client.models.generateContent({ model, contents: [{ role: 'user', parts }] });
      const text = geminiResponseText(response);
      const m = text.match(/\{[\s\S]*\}/);
      if (m) {
        const obj = JSON.parse(m[0]);
        goodVerifyModel = model;
        return { ok: obj.ok !== false, reason: typeof obj.reason === 'string' ? obj.reason.trim().slice(0, 200) : '' };
      }
    } catch (e) {
      console.error('room photo check failed with model ' + model + ':', e && e.message);
      if (e && (e.status === 404 || /NOT_FOUND|no longer available/i.test(String(e.message || '')))) badVerifyModels.add(model);
    }
  }
  return { ok: true, reason: '' };
}

const USER_REFERENCE_RULES = 'Follow the user\'s instruction about this photo precisely: if they say they want exactly this item (for example "точно такой", "именно этот", "exactly this one"), reproduce it faithfully — same shape, same color, same material. If they ask for something similar, place a similar item of the same type and style instead. If their instruction says to change only this one item and keep everything else, do exactly that: modify only what this photo and instruction describe, and leave every other piece of furniture and decor in the room exactly as it is in the original room photo, unchanged.';

function b64ToBuf(img) {
  return { buffer: Buffer.from(img.data, 'base64'), mimetype: img.mimetype };
}

// Проверка одного фото (и главного, и всех фото квартиры) на людей/документы/т.п.
// Принимает уже EXIF-очищенное фото — очистка EXIF остаётся на основном сервере.
app.post('/check-photo', requireSharedSecret, async (req, res) => {
  try {
    const { image, mimetype } = req.body || {};
    if (!image) { res.status(400).json({ error: 'no image' }); return; }
    const result = await checkRoomPhoto(Buffer.from(image, 'base64'), mimetype);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Обычная комната: req.body = { styleGuidance, userComment, palette, referenceImageUrls, referenceNames,
//   mainImage: {data, mimetype}, userRefImage: {data, mimetype} | null }
app.post('/generate', requireSharedSecret, async (req, res) => {
  try {
    const body = req.body || {};
    const styleGuidance = body.styleGuidance || '';
    const userComment = String(body.userComment || '').trim();
    const palette = String(body.palette || '').slice(0, 200);
    const referenceUrls = Array.isArray(body.referenceImageUrls) ? body.referenceImageUrls : [];
    const refNames = Array.isArray(body.referenceNames) ? body.referenceNames : [];
    const { parts: referenceParts, origIndex: refOrigIndex } = await fetchReferenceParts(referenceUrls, 8);
    const refNamesText = referenceParts.length ? 'The last ' + referenceParts.length + ' reference photos, in order, are these catalog products: ' + refOrigIndex.map((o, i) => (i + 1) + ') ' + String(refNames[o] || 'product').slice(0, 120) + mountHint(refNames[o])).join('; ') + '. Reproduce each of them as shown. Ceiling lights, chandeliers and pendant lamps always hang from the ceiling; wall-mounted items are always on the wall; never place them on the floor.' : '';

    const mainImage = b64ToBuf(body.mainImage);
    const userRef = body.userRefImage ? b64ToBuf(body.userRefImage) : null;

    const fullPrompt = [
      'Redesign this exact room photo, using this style guidance as the general direction: ' + styleGuidance + '.',
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the original photo — only change the furniture, decor, materials and colors. Do not extend, widen or reveal any part of the room that is not visible in the original photo — if the photo shows only a corner or a partial view of the room, the result must show that exact same corner or partial view, with the exact same crop and framing, not a wider or different part of the room. Do not invent walls, windows, doors or floor area that are not already visible in the original photo.',
      userComment ? 'THE MOST IMPORTANT INSTRUCTION, follow it exactly and let it override anything below that conflicts with it: the user wrote this specific request: "' + userComment + '". If this request names or implies specific furniture or changes to keep, make, or avoid, follow it precisely. Only the items that this request explicitly asks to keep stay as they are in the original room photo. Every other piece of furniture from the original photo is removed and replaced by the catalog products from the reference photos.' : '',
      userRef ? 'An additional reference photo was supplied by the user, showing the exact item related to their request above. ' + USER_REFERENCE_RULES : '',
      referenceParts.length ? (userComment
        ? 'The last ' + referenceParts.length + ' reference photo(s) show real furniture or decor products from the furniture catalog, matching the overall style. Use them only to style or furnish parts of the room that the user\'s request above does not already cover or ask to keep — never use them to replace or remove anything the user asked to keep unchanged.'
        : 'Each of the last ' + referenceParts.length + ' reference photo(s) shows a real furniture or decor product (sofa, chair, bed, table, wardrobe, shelf, lamp, rug, etc.) from the furniture catalog that must appear in the redesigned room, placed appropriately for its type and matching its exact appearance (shape, material, color) as closely as possible. Every reference item should be included — do not skip any of them. All the main furniture pieces (sofas, beds, wardrobes, tables, chairs, storage units) must come strictly from these reference photos — do not invent or substitute any other furniture. You may add small atmospheric details not shown in the references, such as wallpaper or wall paint, curtains, books, notebooks, plants, cushions or other small decor — but keep these secondary and never let them replace or compete with the main reference furniture. Never add unrelated objects that were not in the original room photo and are not furniture or plain decor — no appliances, no pet items, no electronics, nothing that was not requested. Choose the wall color or wallpaper, floor tone and any added decor so they harmonize with the color palette of the reference furniture — do not use a wall color that clashes with it. The requested color palette is MANDATORY for the whole room: walls, floor accents, textiles, decor AND furniture. Keep the shape and design of each reference product, but if its color clearly clashes with the requested palette, recolor that item to a matching palette color. Strictly avoid any saturated color that is not part of the palette.') : '',
      'This is the most important part regardless of the above: the final image must look like a single real, professionally staged room, not a collage of separate product photos pasted together. Every piece of furniture must rest naturally and fully on the floor or be mounted the way that exact product is actually mounted in real life — never floating, never cut off, never overlapping another object incorrectly. Use one consistent light source, direction and color temperature for the whole scene, with matching shadows and reflections on every item, matching perspective and scale for every piece relative to the room and to each other, so the whole room reads as one coherent, cozy, believable photograph — not a set of furniture items placed next to each other.',
      'Never add any people, human figures, silhouettes, hands, faces, pets, or personal photographs/portraits of people into the room — the result must show only the empty-of-people, staged interior itself.'
    ].filter(Boolean).join(' ');

    const images = [mainImage].concat(userRef ? [userRef] : []).concat(referenceParts);

    const { buffer, mimeType, matched } = await generateChecked(fullPrompt + ' ' + buildStrictRules(referenceParts.length, palette) + ' ' + refNamesText, images, referenceParts, palette);
    res.json({ image: buffer.toString('base64'), mimeType, matched, refOrigIndex });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Фото квартиры (несколько комнат): req.body = { room, budgetPrompt, userComment, referenceImageUrls,
//   referenceNames, mainImage, apartmentImages: [{data, mimetype}, ...], userRefImage }
app.post('/generate-apartment', requireSharedSecret, async (req, res) => {
  try {
    const body = req.body || {};
    const room = body.room || '';
    const budgetPrompt = body.budgetPrompt || '';
    const userComment = String(body.userComment || '').trim();
    const palette = '';
    const referenceUrls = Array.isArray(body.referenceImageUrls) ? body.referenceImageUrls : [];
    const refNames = Array.isArray(body.referenceNames) ? body.referenceNames : [];
    const { parts: referenceParts, origIndex: refOrigIndex } = await fetchReferenceParts(referenceUrls, 6);
    const refNamesText = referenceParts.length ? 'The last ' + referenceParts.length + ' reference photos, in order, are these catalog products: ' + refOrigIndex.map((o, i) => (i + 1) + ') ' + String(refNames[o] || 'product').slice(0, 120) + mountHint(refNames[o])).join('; ') + '. Reproduce each of them as shown. Ceiling lights, chandeliers and pendant lamps always hang from the ceiling; wall-mounted items are always on the wall; never place them on the floor.' : '';

    const targetImage = b64ToBuf(body.mainImage);
    const styleImages = (Array.isArray(body.apartmentImages) ? body.apartmentImages : []).map(b64ToBuf);
    const userRef = body.userRefImage ? b64ToBuf(body.userRefImage) : null;

    const fullPrompt = [
      'The first image is a photo of a room that needs a new interior design: ' + (room || 'a room') + '.',
      referenceParts.length ? (userComment
        ? 'The last ' + referenceParts.length + ' image(s) in this request each show one specific real furniture or decor product from the furniture catalog, matching the overall style. Use them for parts of the room that the user\'s request below does not already cover or ask to keep.'
        : 'This is the single most important instruction, follow it exactly: the last ' + referenceParts.length + ' image(s) in this request each show one specific real furniture or decor product from the furniture catalog. Every main furniture piece in the redesigned room (every sofa, bed, wardrobe, table, chair, storage unit) MUST be exactly that product — same silhouette, same exact color, same exact material and finish as shown in its reference photo, not a similar or reinterpreted version and not a different color. Do not substitute any of them with a different-colored or different-shaped piece. Include every one of these reference items somewhere in the room — do not skip any of them. The requested color palette is MANDATORY for the whole room: walls, floor accents, textiles, decor AND furniture. Keep the shape and design of each reference product, but if its color clearly clashes with the requested palette, recolor that item to a matching palette color. Strictly avoid any saturated color that is not part of the palette.') : '',
      'The next ' + styleImages.length + ' image(s) (before the catalog product photos) show different rooms of the same apartment. Use them ONLY for the wall color or wallpaper, the flooring, the materials and the overall color palette of this home — reuse those exactly. Do NOT copy specific furniture pieces from these apartment photos, and do not let their mood override the exact furniture from the catalog reference photos.',
      userRef ? 'One more image, placed right after the apartment photos and before the catalog product photos, is a reference photo of a furniture or decor item supplied by the user, related to their request below. ' + USER_REFERENCE_RULES : '',
      userComment ? 'THE MOST IMPORTANT INSTRUCTION, follow it exactly and let it override anything above or below that conflicts with it: the user wrote this specific request: "' + userComment + '". If this request names or implies specific furniture or changes to keep, make, or avoid, follow it precisely. Only the items that this request explicitly asks to keep stay as they are in the original room photo. Every other piece of furniture from the original photo is removed and replaced by the catalog products from the reference photos.' : '',
      'At a ' + (budgetPrompt || 'mid-range') + ' furniture budget.',
      'Keep the exact same room layout, walls, windows, doors, proportions and camera angle as in the first photo — only change the furniture, decor, materials and colors. Do not extend, widen or reveal any part of the room that is not visible in the original photo — if the photo shows only a corner or a partial view of the room, the result must show that exact same corner or partial view, with the exact same crop and framing, not a wider or different part of the room. Do not invent walls, windows, doors or floor area that are not already visible in the original photo.',
      'The final image must look like a single real, professionally staged room, not a collage of separate product photos pasted together. Every piece of furniture must rest naturally and fully on the floor or be mounted the way that exact product is actually mounted in real life — never floating, never cut off. Use one consistent light source, direction and color temperature for the whole scene, with matching shadows, perspective and scale, so the room reads as one coherent, believable photograph.',
      'Never add any people, human figures, silhouettes, hands, faces, pets, or personal photographs/portraits of people into the room — the result must show only the empty-of-people, staged interior itself.',
      'Professional interior photography, photorealistic.'
    ].filter(Boolean).join(' ');

    const images = [targetImage].concat(styleImages).concat(userRef ? [userRef] : []).concat(referenceParts);

    const { buffer, mimeType, matched } = await generateChecked(fullPrompt + ' ' + buildStrictRules(referenceParts.length, palette) + ' ' + refNamesText, images, referenceParts, palette);
    res.json({ image: buffer.toString('base64'), mimeType, matched, refOrigIndex });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.get('/', (req, res) => res.send('Room Factory Gemini relay is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('gemini relay listening on port ' + PORT));
