const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {promisify} = require('util');
const {sealData, unsealData} = require('iron-session');

const scrypt = promisify(crypto.scrypt);
const SESSION_COOKIE = 'admin_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;
const loginAttempts = new Map();
let adminPasswordVerifier = null;
const GITHUB_REPOSITORY = 'Rinna1oveu/posmertie-admin-test';
const GITHUB_BRANCH = 'poems-data';
const GITHUB_FILE_PATH = 'data/poems.json';
const GITHUB_FILE_URL = `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${GITHUB_FILE_PATH}`;
const GITHUB_CYCLES_FILE_PATH = 'data/cycles.json';
const GITHUB_CYCLES_FILE_URL = `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${GITHUB_CYCLES_FILE_PATH}`;
const GITHUB_PROSE_FILE_PATH = 'data/prose.json';
const GITHUB_PROSE_FILE_URL = `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${GITHUB_PROSE_FILE_PATH}`;
const GITHUB_IMAGE_CATEGORIES = new Set(['poems','prose','cycles']);
const MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024;
// Serialize all GitHub content mutations in this process. Image reference checks
// and deletion must not interleave with edits to poems, prose, or cycles.
let githubWriteQueue = Promise.resolve();
const publishedImageSettingsCache = new Map();

function queueGitHubMutation(mutate){
  const operation = githubWriteQueue.then(mutate);
  githubWriteQueue = operation.then(()=>undefined,()=>undefined);
  return operation;
}

function invalidatePublishedImageCache(...categories){
  for(const category of categories) publishedImageSettingsCache.delete(category);
}

async function initializeAdminPasswordVerifier(){
  let password = process.env.ADMIN_PASSWORD || '';
  delete process.env.ADMIN_PASSWORD;

  if(!password || !process.env.ADMIN_USERNAME){
    password = '';
    return;
  }

  const salt = crypto.randomBytes(16);
  try{
    const key = await scrypt(password, salt, 64, {N:32768, r:8, p:1, maxmem:64 * 1024 * 1024});
    adminPasswordVerifier = {salt, key};
  }finally{
    password = '';
  }
}

function getSessionPassword(){
  return process.env.ADMIN_SESSION_SECRET || '';
}

function getSessionCookie(req){
  const cookies = (req.headers.cookie || '').split(';');
  const prefix = SESSION_COOKIE + '=';
  const entry = cookies.find(cookie=>cookie.trim().startsWith(prefix));
  if(!entry) return '';
  try{
    return decodeURIComponent(entry.trim().slice(prefix.length));
  }catch{
    return '';
  }
}

function setSessionCookie(res, value, maxAge=SESSION_TTL_SECONDS){
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);
}

async function getSession(req){
  const cookie = getSessionCookie(req);
  const password = getSessionPassword();
  if(!cookie || password.length < 32) return null;

  try{
    const session = await unsealData(cookie, {password, ttl:SESSION_TTL_SECONDS});
    if(session.username !== process.env.ADMIN_USERNAME) return null;
    return session;
  }catch{
    return null;
  }
}

function getClientIp(req){
  const forwardedFor = req.headers['x-forwarded-for'];
  if(typeof forwardedFor === 'string' && forwardedFor.trim()){
    return forwardedFor.split(',')[0].trim().slice(0, 100);
  }
  return req.socket.remoteAddress || 'unknown';
}

function isSameOrigin(req){
  const origin = req.headers.origin;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if(typeof origin !== 'string' || typeof host !== 'string') return false;

  try{
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === 'https:' && parsedOrigin.host.toLowerCase() === host.toLowerCase();
  }catch{
    return false;
  }
}

function getLoginAttempt(ip){
  const now = Date.now();
  for(const [key, attempt] of loginAttempts){
    if(now - attempt.windowStartedAt >= LOGIN_WINDOW_MS) loginAttempts.delete(key);
  }

  let attempt = loginAttempts.get(ip);
  if(!attempt || now - attempt.windowStartedAt >= LOGIN_WINDOW_MS){
    attempt = {count:0, windowStartedAt:now};
    loginAttempts.set(ip, attempt);
    if(loginAttempts.size > 10000){
      const oldestIp = loginAttempts.keys().next().value;
      loginAttempts.delete(oldestIp);
    }
  }

  return attempt;
}

async function verifyAdminPassword(password){
  if(!adminPasswordVerifier) return false;

  try{
    const actual = await scrypt(password, adminPasswordVerifier.salt, 64, {N:32768, r:8, p:1, maxmem:64 * 1024 * 1024});
    return crypto.timingSafeEqual(actual, adminPasswordVerifier.key);
  }catch{
    return false;
  }
}

function sendJson(res, status, value){
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store'});
  res.end(JSON.stringify(value));
}

function githubApiError(status, code){
  const error = new Error('GitHub API request failed');
  error.status = status;
  error.code = code;
  return error;
}

function getPoemId(poem, index){
  if(typeof poem.id === 'string' && poem.id) return poem.id;
  const legacyData = {...poem};
  delete legacyData.id;
  const signature = `${index}\0${JSON.stringify(legacyData)}`;
  return `legacy-${crypto.createHash('sha256').update(signature).digest('hex').slice(0, 24)}`;
}

async function githubRequest(method, body, fileUrl=GITHUB_FILE_URL,accept='application/vnd.github+json',timeoutMs=15000){
  const token = process.env.GITHUB_TOKEN;
  if(!token) throw githubApiError(503, 'GITHUB_TOKEN_MISSING');

  const headers = {
    'Accept':accept,
    'Authorization':`Bearer ${token}`,
    'X-GitHub-Api-Version':'2022-11-28'
  };
  const options = {
    method,
    headers,
    signal:AbortSignal.timeout(timeoutMs)
  };

  if(body){
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const url = method === 'GET'
    ? `${fileUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`
    : fileUrl;
  return fetch(url, options);
}

function getGitHubContentsUrl(filePath){
  const encodedPath = filePath.split('/').map(segment=>encodeURIComponent(segment)).join('/');
  return `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${encodedPath}`;
}

function getManagedImageInfo(imagePath,category){
  if(typeof category !== 'string' || !GITHUB_IMAGE_CATEGORIES.has(category) || typeof imagePath !== 'string') return null;
  const match = imagePath.match(/^\/images\/(poems|prose|cycles)\/([a-f0-9]{64})\.(jpe?g|png|webp)$/i);
  if(!match || match[1] !== category) return null;
  const extension = match[3].toLowerCase();
  return {category:match[1],hash:match[2].toLowerCase(),extension,filePath:`images/${match[1]}/${match[2].toLowerCase()}.${extension}`};
}

function imageExtensionForName(fileName){
  if(typeof fileName !== 'string' || fileName.length > 255 || /[\\/]/.test(fileName)) return '';
  const extension = path.extname(fileName).toLowerCase();
  return ['.jpg','.jpeg','.png','.webp'].includes(extension) ? extension.slice(1) : '';
}

function imageBytesMatchType(bytes,extension){
  if(extension === 'jpg' || extension === 'jpeg') return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if(extension === 'png') return bytes.length >= 8 && bytes.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  if(extension === 'webp') return bytes.length >= 12 && bytes.toString('ascii',0,4) === 'RIFF' && bytes.toString('ascii',8,12) === 'WEBP';
  return false;
}

function getImageDimensions(bytes,extension){
  let width = 0;
  let height = 0;
  if(extension === 'png' && bytes.length >= 24){
    width = bytes.readUInt32BE(16);
    height = bytes.readUInt32BE(20);
  }else if(extension === 'jpg' || extension === 'jpeg'){
    let offset = 2;
    while(offset + 9 < bytes.length){
      if(bytes[offset] !== 0xff){offset++;continue;}
      while(offset < bytes.length && bytes[offset] === 0xff) offset++;
      const marker = bytes[offset++];
      if(marker === 0xd8 || marker === 0xd9 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if(offset + 1 >= bytes.length) break;
      const segmentLength = bytes.readUInt16BE(offset);
      if(segmentLength < 2 || offset + segmentLength > bytes.length) break;
      if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker) && segmentLength >= 7){
        height = bytes.readUInt16BE(offset + 3);
        width = bytes.readUInt16BE(offset + 5);
        break;
      }
      offset += segmentLength;
    }
  }else if(extension === 'webp' && bytes.length >= 30){
    const chunk = bytes.toString('ascii',12,16);
    if(chunk === 'VP8X'){
      width = 1 + bytes.readUIntLE(24,3);
      height = 1 + bytes.readUIntLE(27,3);
    }else if(chunk === 'VP8L' && bytes[20] === 0x2f){
      width = 1 + bytes[21] + ((bytes[22] & 0x3f) << 8);
      height = 1 + ((bytes[22] >> 6) | (bytes[23] << 2) | ((bytes[24] & 0x0f) << 10));
    }else if(chunk === 'VP8 ' && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a){
      width = bytes.readUInt16LE(26) & 0x3fff;
      height = bytes.readUInt16LE(28) & 0x3fff;
    }
  }
  if(!Number.isInteger(width) || width < 1 || width > 100000 || !Number.isInteger(height) || height < 1 || height > 100000) return {width:1000,height:750};
  return {width,height};
}

function renderPublicWatermarkedImage(bytes,extension,settings){
  const {width,height} = getImageDimensions(bytes,extension);
  const watermarkOn = settings.imageWatermark;
  const archiveOn = settings.imageEffect === 'archive' && settings.imageArchiveMarkup;
  if(!watermarkOn && !archiveOn) return {bytes,contentType:extension === 'jpg' || extension === 'jpeg' ? 'image/jpeg' : `image/${extension}`};
  const opacity = Math.max(0,Math.min(100,settings.imageWatermarkOpacity)) / 100;
  const margin = Math.max(12,Math.round(Math.min(width,height) * .035));
  const fontSize = Math.max(18,Math.min(72,Math.round(Math.min(width,height) * .055)));
  const positions = {
    'top-left':{x:margin,y:margin + fontSize,anchor:'start'},
    'top-right':{x:width - margin,y:margin + fontSize,anchor:'end'},
    center:{x:Math.round(width / 2),y:Math.round(height / 2),anchor:'middle'},
    'bottom-left':{x:margin,y:height - margin,anchor:'start'},
    'bottom-right':{x:width - margin,y:height - margin,anchor:'end'}
  };
  const position = positions[settings.imageWatermarkPosition] || positions['bottom-right'];
  const mime = extension === 'jpg' || extension === 'jpeg' ? 'image/jpeg' : `image/${extension}`;
  const escapeXml = value=>String(value || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
  let archiveMarkup = '';
  if(archiveOn){
    const label = escapeXml(settings.visualRecordLabel || '');
    const corner = escapeXml(settings.imageCornerLabel || '');
    const parts = [settings.imageMetaPrefix,settings.imageMetaSection,settings.imageMetaTitle].map(value=>typeof value === 'string' ? value.trim() : '').filter(Boolean);
    const meta = parts.length ? `// ${escapeXml(parts.join(' // '))} //` : '';
    const metaWidth = Math.max(80,width - margin * 2 - 26);
    const footer = meta ? `<path d="M ${margin} ${height - margin - fontSize * .85} v ${fontSize * .85}" stroke="#ee2349" stroke-width="2"/><text x="${margin + 14}" y="${height - margin}" fill="#f4e8eb" font-family="Arial,sans-serif" font-size="${Math.max(10,Math.min(15,Math.round(fontSize * .28)))}" letter-spacing="1.2" textLength="${Math.min(metaWidth,Math.max(1,meta.length * fontSize * .17))}" lengthAdjust="spacingAndGlyphs">${meta}</text>` : '';
    archiveMarkup = `<defs><pattern id="archiveGrid" width="48" height="48" patternUnits="userSpaceOnUse"><path d="M 48 0 L 0 0 0 48" fill="none" stroke="#fff" stroke-opacity=".075" stroke-width=".7"/><path d="M 24 0 V 48 M 0 24 H 48" fill="none" stroke="#ee2349" stroke-opacity=".035" stroke-width=".6"/></pattern></defs><rect width="${width}" height="${height}" fill="url(#archiveGrid)"/><rect x="1" y="1" width="${width - 2}" height="${height - 2}" fill="none" stroke="#92283d" stroke-opacity=".9" stroke-width="2"/><path d="M ${margin} ${margin} h ${Math.max(18,Math.round(fontSize * .65))} M ${margin} ${margin} v ${Math.max(18,Math.round(fontSize * .65))} M ${width - margin} ${height - margin} h -${Math.max(18,Math.round(fontSize * .65))} M ${width - margin} ${height - margin} v -${Math.max(18,Math.round(fontSize * .65))}" fill="none" stroke="#ee2349" stroke-opacity=".65" stroke-width="1"/>${label ? `<text x="${margin}" y="${margin + fontSize}" fill="#f7e9ec" font-family="Arial,sans-serif" font-size="${Math.max(10,Math.min(18,Math.round(fontSize * .32)))}" font-weight="700" letter-spacing="2">${label}</text>` : ''}${corner ? `<text x="${width - margin}" y="${margin + fontSize}" text-anchor="end" fill="#f07a8e" font-family="Arial,sans-serif" font-size="${Math.max(10,Math.min(17,Math.round(fontSize * .3)))}" font-weight="700" letter-spacing="1.4">${corner}</text>` : ''}${footer}`;
  }
  const imageFilter = settings.imageEffect === 'archive' ? `brightness(${Math.max(0,.88 * (1 - settings.imageOverlay / 100 * .65))})` : settings.imageEffect === 'darken' ? `brightness(${Math.max(0,1 - settings.imageIntensity / 100 * .65)})` : 'none';
  const watermark = watermarkOn ? `<text x="${position.x}" y="${position.y}" text-anchor="${position.anchor}" fill="#fff" fill-opacity="${opacity}" stroke="#000" stroke-opacity="${Math.min(.72,opacity)}" stroke-width="${Math.max(1,Math.round(fontSize * .07))}" paint-order="stroke" font-family="Georgia, 'Times New Roman', serif" font-size="${fontSize}" font-weight="700">© Ринна</text>` : '';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" style="user-select:none;-webkit-user-select:none"><image x="0" y="0" width="${width}" height="${height}" preserveAspectRatio="none" href="data:${mime};base64,${bytes.toString('base64')}" style="filter:${imageFilter}"/>${archiveMarkup}${watermark}</svg>`;
  return {bytes:Buffer.from(svg,'utf8'),contentType:'image/svg+xml; charset=utf-8'};
}

async function readGitHubImage(filePath){
  const fileUrl = getGitHubContentsUrl(filePath);
  const response = await githubRequest('GET',undefined,fileUrl,'application/vnd.github.object+json',60000);
  if(response.status === 404) return null;
  if(!response.ok) throw githubApiError(response.status,'GITHUB_IMAGE_READ_FAILED');
  try{
    const file = await response.json();
    if(typeof file.sha !== 'string') throw new Error('Invalid image response');
    if(file.encoding === 'base64' && typeof file.content === 'string' && file.content.trim()){
      return {sha:file.sha,bytes:Buffer.from(file.content.replace(/\s/g,''),'base64')};
    }
    const rawResponse = await githubRequest('GET',undefined,fileUrl,'application/vnd.github.raw+json',60000);
    if(!rawResponse.ok) throw githubApiError(rawResponse.status,'GITHUB_IMAGE_READ_FAILED');
    return {sha:file.sha,bytes:Buffer.from(await rawResponse.arrayBuffer())};
  }catch(error){
    if(error.status) throw error;
    throw githubApiError(502,'INVALID_GITHUB_IMAGE_FILE');
  }
}

async function writeGitHubImage(filePath,bytes){
  const body = {
    message:`Add image ${path.basename(filePath)}`,
    content:bytes.toString('base64'),
    branch:GITHUB_BRANCH
  };
  const response = await githubRequest('PUT',body,getGitHubContentsUrl(filePath),undefined,60000);
  if(!response.ok) throw githubApiError(response.status,'GITHUB_IMAGE_WRITE_FAILED');
}

async function uploadImageToGitHub(category,fileName,contentType,contentBase64){
  if(!GITHUB_IMAGE_CATEGORIES.has(category)) throw githubApiError(400,'INVALID_IMAGE_CATEGORY');
  const extension = imageExtensionForName(fileName);
  if(!extension) throw githubApiError(400,'INVALID_IMAGE_FORMAT');
  if(typeof contentBase64 !== 'string' || !contentBase64.length || contentBase64.length > Math.ceil(MAX_IMAGE_SIZE_BYTES / 3) * 4 + 8 || contentBase64.length % 4 !== 0){
    throw githubApiError(400,'INVALID_IMAGE_DATA');
  }
  const padding = contentBase64.endsWith('==') ? 2 : contentBase64.endsWith('=') ? 1 : 0;
  const dataLength = contentBase64.length - padding;
  if(contentBase64.indexOf('=') !== (padding ? dataLength : -1) || !/^[A-Za-z0-9+/]+$/.test(contentBase64.slice(0,dataLength)) || (padding === 1 && dataLength % 4 !== 3) || (padding === 2 && dataLength % 4 !== 2)){
    throw githubApiError(400,'INVALID_IMAGE_DATA');
  }
  const bytes = Buffer.from(contentBase64,'base64');
  if(!bytes.length || bytes.length > MAX_IMAGE_SIZE_BYTES) throw githubApiError(413,'IMAGE_SIZE_LIMIT');
  if(bytes.toString('base64') !== contentBase64) throw githubApiError(400,'INVALID_IMAGE_DATA');
  const expectedMime = extension === 'jpg' || extension === 'jpeg' ? 'image/jpeg' : `image/${extension}`;
  if(contentType !== expectedMime) throw githubApiError(400,'INVALID_IMAGE_FORMAT');
  if(!imageBytesMatchType(bytes,extension)) throw githubApiError(400,'INVALID_IMAGE_FORMAT');

  const hash = crypto.createHash('sha256').update(bytes).digest('hex');
  const filePath = `images/${category}/${hash}.${extension}`;
  for(let attempt=0;attempt<3;attempt++){
    const existing = await readGitHubImage(filePath);
    if(existing){
      const existingHash = crypto.createHash('sha256').update(existing.bytes).digest('hex');
      if(existingHash !== hash) throw githubApiError(409,'GITHUB_IMAGE_HASH_CONFLICT');
      return {image:`/${filePath}`,imageName:fileName.replace(/[^\p{L}\p{N}._ -]/gu,'_').slice(0,255),imageSize:bytes.length};
    }
    try{
      await writeGitHubImage(filePath,bytes);
      return {image:`/${filePath}`,imageName:fileName.replace(/[^\p{L}\p{N}._ -]/gu,'_').slice(0,255),imageSize:bytes.length};
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }
  throw githubApiError(409,'GITHUB_IMAGE_WRITE_CONFLICT');
}

async function imageIsReferenced(category,imagePath){
  if(category === 'poems'){
    const {poems} = await readPoemsFromGitHub();
    return poems.some(poem=>poem.image === imagePath);
  }
  if(category === 'prose'){
    const {prose} = await readProseFromGitHub();
    return prose.some(entry=>entry.image === imagePath);
  }
  const {cycles} = await readCyclesFromGitHub();
  return cycles.some(cycle=>cycle.image === imagePath || cycle.cover === imagePath);
}

async function getPublishedImageReferences(category,imagePath){
  const now = Date.now();
  let cached = publishedImageSettingsCache.get(category);
  if(!cached || (cached.expiresAt <= now && !cached.promise)){
    cached = {expiresAt:0,settings:null,promise:null};
    const promise = (async()=>{
      let entries;
      if(category === 'poems'){
        const {poems} = await readPoemsFromGitHub();
        entries = poems.map((poem,index)=>[poem.image,poem,getPoemId(poem,index)]).filter(([imagePath,poem])=>poem.status !== 'draft' && imagePath);
      }else if(category === 'prose'){
        const {prose} = await readProseFromGitHub();
        entries = prose.map((entry,index)=>[entry.image,entry,getProseId(entry,index)]).filter(([imagePath,entry])=>entry.status !== 'draft' && imagePath);
      }else{
        const {cycles} = await readCyclesFromGitHub();
        entries = cycles.map((cycle,index)=>[cycle,index]).filter(([cycle])=>cycle.status !== 'draft').flatMap(([cycle,index])=>[[cycle.image,cycle,getCycleId(cycle,index)],[cycle.cover,cycle,getCycleId(cycle,index)]]).filter(([imagePath])=>imagePath);
      }
      cached.settings = new Map();
      for(const [pathValue,record,id] of entries){
        if(typeof pathValue !== 'string' || !pathValue) continue;
        if(!cached.settings.has(pathValue)) cached.settings.set(pathValue,[]);
        const contentKind = category === 'poems' ? 'poem' : category === 'cycles' ? 'cycle' : 'prose';
        cached.settings.get(pathValue).push({id,settings:getImagePresentationSettings(record,contentKind)});
      }
      cached.expiresAt = Date.now() + 30_000;
      return cached.settings;
    })();
    cached.promise = promise;
    publishedImageSettingsCache.set(category,cached);
    try{await promise;}catch(error){publishedImageSettingsCache.delete(category);throw error;}finally{cached.promise = null;}
  }else if(cached.promise){
    await cached.promise;
  }
  return cached.settings && cached.settings.has(imagePath) ? cached.settings.get(imagePath) : [];
}

async function getPublishedRecordImage(type,id){
  let category;
  let record;
  if(type === 'poem'){
    category = 'poems';
    const {poems} = await readPoemsFromGitHub();
    const index = poems.findIndex((poem,position)=>getPoemId(poem,position) === id);
    if(index >= 0) record = poems[index];
  }else if(type === 'prose'){
    category = 'prose';
    const {prose} = await readProseFromGitHub();
    const index = prose.findIndex((entry,position)=>getProseId(entry,position) === id);
    if(index >= 0) record = prose[index];
  }else if(type === 'cycle'){
    category = 'cycles';
    const {cycles} = await readCyclesFromGitHub();
    const index = cycles.findIndex((cycle,position)=>getCycleId(cycle,position) === id);
    if(index >= 0) record = cycles[index];
  }
  if(!record || record.status === 'draft') return null;
  const imagePath = typeof record.image === 'string' && record.image ? record.image : (category === 'cycles' && typeof record.cover === 'string' ? record.cover : '');
  const info = getManagedImageInfo(imagePath,category);
  if(!info) return null;
  return {info,settings:getImagePresentationSettings(record,category === 'poems' ? 'poem' : category === 'cycles' ? 'cycle' : 'prose')};
}

async function sendPublicImage(res,info,settings){
  const imageFile = await readGitHubImage(info.filePath);
  if(!imageFile){sendJson(res,404,{error:'Изображение не найдено'});return;}
  const image = renderPublicWatermarkedImage(imageFile.bytes,info.extension,settings);
  res.writeHead(200,{
    'Content-Type':image.contentType,
    'Content-Length':image.bytes.length,
    'Cache-Control':'public, max-age=300',
    'Content-Disposition':'inline',
    'Referrer-Policy':'no-referrer',
    'X-Content-Type-Options':'nosniff'
  });
  res.end(image.bytes);
}

async function deleteImageFromGitHub(category,imagePath){
  const info = getManagedImageInfo(imagePath,category);
  if(!info) throw githubApiError(400,'INVALID_IMAGE_PATH');
  if(await imageIsReferenced(category,imagePath)) throw githubApiError(409,'IMAGE_IN_USE');
  const fileUrl = getGitHubContentsUrl(info.filePath);
  for(let attempt=0;attempt<3;attempt++){
    const existing = await readGitHubImage(info.filePath);
    if(!existing) return {deleted:false};
    const response = await githubRequest('DELETE',{
      message:`Remove image ${path.basename(info.filePath)}`,
      sha:existing.sha,
      branch:GITHUB_BRANCH
    },fileUrl,undefined,60000);
    if(response.ok) return {deleted:true};
    if((response.status === 409 || response.status === 422) && attempt < 2) continue;
    throw githubApiError(response.status,'GITHUB_IMAGE_DELETE_FAILED');
  }
  throw githubApiError(409,'GITHUB_IMAGE_DELETE_CONFLICT');
}

function queueImageMutation(mutate){
  return queueGitHubMutation(mutate);
}

function sendImageMutationError(res,error){
  if(error.code === 'GITHUB_TOKEN_MISSING'){
    sendJson(res,503,{error:'Хранилище изображений не настроено'});
    return;
  }
  const clientErrors = new Map([
    ['INVALID_IMAGE_CATEGORY',[400,'Выберите допустимый раздел для изображения']],
    ['INVALID_IMAGE_FORMAT',[400,'Поддерживаются только JPG, JPEG, PNG и WebP']],
    ['INVALID_IMAGE_DATA',[400,'Не удалось прочитать файл изображения']],
    ['INVALID_IMAGE_PATH',[400,'Недопустимый путь к изображению']],
    ['IMAGE_SIZE_LIMIT',[413,'Размер изображения не должен превышать 10 MiB']],
    ['IMAGE_IN_USE',[409,'Изображение используется в сохранённой записи']],
    ['GITHUB_IMAGE_HASH_CONFLICT',[409,'Не удалось безопасно сохранить изображение']],
    ['GITHUB_IMAGE_WRITE_CONFLICT',[409,'Изображение изменилось в GitHub. Повторите попытку']],
    ['GITHUB_IMAGE_DELETE_CONFLICT',[409,'Изображение изменилось в GitHub. Повторите попытку']]
  ]);
  const response = clientErrors.get(error.code);
  if(response){
    sendJson(res,response[0],{error:response[1]});
    return;
  }
  if(error.status) console.error(`GitHub image operation failed with status ${error.status}`);
  else console.error('GitHub image operation failed');
  sendJson(res,502,{error:'Не удалось выполнить операцию с изображением'});
}

async function readPoemsFromGitHub(){
  const response = await githubRequest('GET');
  if(response.status === 404) return {poems:[], sha:null};
  if(!response.ok) throw githubApiError(response.status);

  try{
    const file = await response.json();
    if(file.encoding !== 'base64' || typeof file.content !== 'string' || typeof file.sha !== 'string'){
      throw new Error('Invalid file response');
    }
    const content = Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
    const poems = JSON.parse(content);
    if(!Array.isArray(poems) || poems.some(poem=>!poem || typeof poem !== 'object' || Array.isArray(poem))){
      throw new Error('Invalid poems data');
    }
    const poemsWithIds = poems.map((poem,index)=>({...poem,id:getPoemId(poem,index)}));
    return {poems:poemsWithIds, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_FILE');
  }
}

async function writePoemsToGitHub(poems, sha, message='Update poems from admin panel'){
  const body = {
    message,
    content:Buffer.from(JSON.stringify(poems, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body);
  if(!response.ok) throw githubApiError(response.status);
}

async function mutatePoemsOnGitHub(mutate, message){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readPoemsFromGitHub();
    const poems = mutate(current.poems);

    try{
      await writePoemsToGitHub(poems, current.sha, message);
      return poems;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_WRITE_CONFLICT');
}

function queuePoemMutation(mutate, message){
  return queueGitHubMutation(()=>mutatePoemsOnGitHub(mutate, message)).then(result=>{
    invalidatePublishedImageCache('poems');
    return result;
  });
}

const DEFAULT_IMAGE_SETTINGS = Object.freeze({imageEffect:'none',imagePosition:'center',imageScale:100,imageIntensity:50,imageOverlay:0,imageHover:'none'});
const DEFAULT_IMAGE_WATERMARK_SETTINGS = Object.freeze({imageWatermark:true,imageWatermarkOpacity:42,imageWatermarkPosition:'bottom-right'});
const DEFAULT_IMAGE_ARCHIVE_SETTINGS = Object.freeze({imageArchiveMarkup:true,visualRecordLabel:'',imageMetaPrefix:'ИЛЛЮСТРАЦИЯ',imageMetaSection:'',imageMetaTitle:'',imageCornerLabel:''});
const IMAGE_PRESENTATION_FIELDS = ['imageCaption','imageEffect','imagePosition','imageScale','imageIntensity','imageOverlay','imageHover','imageWatermark','imageWatermarkOpacity','imageWatermarkPosition','imageArchiveMarkup','visualRecordLabel','imageMetaPrefix','imageMetaSection','imageMetaTitle','imageCornerLabel'];
const IMAGE_EFFECTS = new Set(['none','fade','darken','scale','zoom','glow','archive']);
const IMAGE_POSITIONS = new Set(['center','top','bottom','left','right']);
const IMAGE_HOVER_EFFECTS = new Set(['none','scale','zoom','glow']);
const IMAGE_WATERMARK_POSITIONS = new Set(['top-left','top-right','center','bottom-left','bottom-right']);

function defaultVisualRecordLabel(contentKind){
  if(contentKind === 'poem') return 'POEM // VISUAL RECORD';
  if(contentKind === 'cycle') return 'CYCLE // VISUAL RECORD';
  return 'CHAPTER // VISUAL RECORD';
}

function getImageArchiveSettings(input={},contentKind='poem',isNew=false){
  const record = input && typeof input === 'object' ? input : {};
  const defaultSection = isNew ? (contentKind === 'poem' ? 'СТИХОТВОРЕНИЕ' : contentKind === 'cycle' ? 'ЦИКЛ' : '') : '';
  return {
    imageArchiveMarkup:typeof record.imageArchiveMarkup === 'boolean' ? record.imageArchiveMarkup : DEFAULT_IMAGE_ARCHIVE_SETTINGS.imageArchiveMarkup,
    visualRecordLabel:typeof record.visualRecordLabel === 'string' ? record.visualRecordLabel.trim().slice(0,160) : defaultVisualRecordLabel(contentKind),
    imageMetaPrefix:typeof record.imageMetaPrefix === 'string' ? record.imageMetaPrefix.trim().slice(0,80) : DEFAULT_IMAGE_ARCHIVE_SETTINGS.imageMetaPrefix,
    imageMetaSection:typeof record.imageMetaSection === 'string' ? record.imageMetaSection.trim().slice(0,120) : defaultSection,
    imageMetaTitle:typeof record.imageMetaTitle === 'string' ? record.imageMetaTitle.trim().slice(0,160) : '',
    imageCornerLabel:typeof record.imageCornerLabel === 'string' ? record.imageCornerLabel.trim().slice(0,100) : ''
  };
}

function getImagePresentationSettings(input={},contentKind='poem'){
  const record = input && typeof input === 'object' ? input : {};
  const effect = record.imageEffect === 'zoom' ? 'scale' : record.imageEffect;
  return {
    ...getImageWatermarkSettings(record),
    imageEffect:IMAGE_EFFECTS.has(effect) ? effect : DEFAULT_IMAGE_SETTINGS.imageEffect,
    imageIntensity:Number.isInteger(Number(record.imageIntensity)) && Number(record.imageIntensity) >= 0 && Number(record.imageIntensity) <= 100 ? Number(record.imageIntensity) : DEFAULT_IMAGE_SETTINGS.imageIntensity,
    imageOverlay:Number.isInteger(Number(record.imageOverlay)) && Number(record.imageOverlay) >= 0 && Number(record.imageOverlay) <= 100 ? Number(record.imageOverlay) : DEFAULT_IMAGE_SETTINGS.imageOverlay,
    ...getImageArchiveSettings(record,contentKind,false)
  };
}

function getImageWatermarkSettings(record={}){
  const input = record && typeof record === 'object' ? record : {};
  return {
    imageWatermark:typeof input.imageWatermark === 'boolean' ? input.imageWatermark : DEFAULT_IMAGE_WATERMARK_SETTINGS.imageWatermark,
    imageWatermarkOpacity:Number.isInteger(Number(input.imageWatermarkOpacity)) && Number(input.imageWatermarkOpacity) >= 0 && Number(input.imageWatermarkOpacity) <= 100 ? Number(input.imageWatermarkOpacity) : DEFAULT_IMAGE_WATERMARK_SETTINGS.imageWatermarkOpacity,
    imageWatermarkPosition:IMAGE_WATERMARK_POSITIONS.has(input.imageWatermarkPosition) ? input.imageWatermarkPosition : DEFAULT_IMAGE_WATERMARK_SETTINGS.imageWatermarkPosition
  };
}

function preserveOmittedImagePresentation(existing,input){
  const preserved = {};
  for(const field of IMAGE_PRESENTATION_FIELDS){
    if(Object.prototype.hasOwnProperty.call(input,field)) continue;
    if(Object.prototype.hasOwnProperty.call(existing,field)) preserved[field] = existing[field];
    else if(field === 'imageCaption' && typeof existing.caption === 'string') preserved.imageCaption = existing.caption;
  }
  return preserved;
}

function validateImageSettings(input,contentKind='poem'){
  if(input.imageWatermark !== undefined && typeof input.imageWatermark !== 'boolean') return {error:'Настройка watermark должна быть включена или выключена'};
  if(input.imageWatermarkOpacity !== undefined && (!Number.isInteger(input.imageWatermarkOpacity) || input.imageWatermarkOpacity < 0 || input.imageWatermarkOpacity > 100)) return {error:'Прозрачность watermark должна быть от 0 до 100%'};
  if(input.imageWatermarkPosition !== undefined && !IMAGE_WATERMARK_POSITIONS.has(input.imageWatermarkPosition)) return {error:'Неизвестная позиция watermark'};
  if(input.imageArchiveMarkup !== undefined && typeof input.imageArchiveMarkup !== 'boolean') return {error:'Настройка архивной разметки должна быть включена или выключена'};
  for(const field of ['visualRecordLabel','imageMetaPrefix','imageMetaSection','imageMetaTitle','imageCornerLabel']) if(input[field] !== undefined && typeof input[field] !== 'string') return {error:'Технические метки должны быть текстом'};
  const fieldLimits = {visualRecordLabel:160,imageMetaPrefix:80,imageMetaSection:120,imageMetaTitle:160,imageCornerLabel:100};
  for(const [field,limit] of Object.entries(fieldLimits)) if(typeof input[field] === 'string' && input[field].trim().length > limit) return {error:'Техническая метка слишком длинная'};
  const settings = {
    imageEffect:input.imageEffect === undefined ? DEFAULT_IMAGE_SETTINGS.imageEffect : (input.imageEffect === 'zoom' ? 'scale' : input.imageEffect),
    imagePosition:input.imagePosition === undefined ? DEFAULT_IMAGE_SETTINGS.imagePosition : input.imagePosition,
    imageScale:input.imageScale === undefined ? DEFAULT_IMAGE_SETTINGS.imageScale : Number(input.imageScale),
    imageIntensity:input.imageIntensity === undefined ? DEFAULT_IMAGE_SETTINGS.imageIntensity : Number(input.imageIntensity),
    imageOverlay:input.imageOverlay === undefined ? DEFAULT_IMAGE_SETTINGS.imageOverlay : Number(input.imageOverlay),
    imageHover:input.imageHover === undefined ? DEFAULT_IMAGE_SETTINGS.imageHover : (input.imageHover === 'zoom' ? 'scale' : input.imageHover),
    ...getImageWatermarkSettings(input),
    ...getImageArchiveSettings(input,contentKind,false)
  };
  if(!IMAGE_EFFECTS.has(settings.imageEffect) || !IMAGE_POSITIONS.has(settings.imagePosition) || !IMAGE_HOVER_EFFECTS.has(settings.imageHover)) return {error:'Неизвестный эффект или позиция изображения'};
  if(!Number.isInteger(settings.imageScale) || settings.imageScale < 80 || settings.imageScale > 150) return {error:'Масштаб изображения должен быть от 80 до 150%'};
  if(!Number.isInteger(settings.imageIntensity) || settings.imageIntensity < 0 || settings.imageIntensity > 100) return {error:'Интенсивность эффекта должна быть от 0 до 100%'};
  if(!Number.isInteger(settings.imageOverlay) || settings.imageOverlay < 0 || settings.imageOverlay > 100) return {error:'Затемнение должно быть от 0 до 100%'};
  if(typeof settings.imageWatermark !== 'boolean' || !Number.isInteger(settings.imageWatermarkOpacity) || settings.imageWatermarkOpacity < 0 || settings.imageWatermarkOpacity > 100 || !IMAGE_WATERMARK_POSITIONS.has(settings.imageWatermarkPosition)) return {error:'Некорректные настройки watermark'};
  return {settings};
}

function validateImageMetadata(input){
  const imageName = typeof input.imageName === 'string' ? input.imageName.slice(0,255) : '';
  const imageSize = input.imageSize === undefined || input.imageSize === '' ? 0 : Number(input.imageSize);
  if(!Number.isSafeInteger(imageSize) || imageSize < 0 || imageSize > MAX_IMAGE_SIZE_BYTES) return {error:'Размер изображения должен быть не больше 10 MiB'};
  return {imageName,imageSize};
}

function validatePoem(input){
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const text = typeof input.text === 'string' ? input.text.trim() : '';
  const date = typeof input.date === 'string' ? input.date.trim() : '';
  const status = input.status === undefined ? 'published' : input.status;
  const image = typeof input.image === 'string' ? input.image.trim() : '';
  const captionValue = typeof input.imageCaption === 'string' ? input.imageCaption : input.caption;
  const caption = typeof captionValue === 'string' ? captionValue.trim() : '';
  const imageSettings = validateImageSettings(input,'poem');
  const imageMetadata = validateImageMetadata(input);

  if(!title || !text) return {error:'Название и текст обязательны'};
  if(title.length > 300 || text.length > 1000000) return {error:'Название или текст слишком длинные'};
  if(date){
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return {error:'Укажите корректную дату'};
    const parsedDate = new Date(date + 'T00:00:00.000Z');
    if(Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0,10) !== date) return {error:'Укажите корректную дату'};
  }
  if(status !== 'published' && status !== 'draft') return {error:'Неизвестный статус стихотворения'};
  if(image.length > 2048 || caption.length > 500) return {error:'Ссылка или подпись к иллюстрации слишком длинная'};
  if(imageSettings.error) return imageSettings;
  if(imageMetadata.error) return imageMetadata;
  const hasUnsupportedScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(image) && !image.startsWith('http://') && !image.startsWith('https://');
  if(image && (hasUnsupportedScheme || !(image.startsWith('http://') || image.startsWith('https://') || image.startsWith('/') || /^[a-zA-Z0-9._-]/.test(image)))) return {error:'Укажите ссылку или путь к изображению'};

  return {poem:{title,text,date,status,image,caption,imageCaption:caption,...imageSettings.settings,...imageMetadata}};
}

function sendPoemMutationError(res, error){
  if(error.code === 'POEM_NOT_FOUND'){
    sendJson(res, 404, {error:'Стихотворение не найдено'});
    return;
  }
  sendGitHubError(res, error, 'write');
}

function getCycleId(cycle, index){
  if(typeof cycle.id === 'string' && cycle.id) return cycle.id;
  const legacyData = {...cycle};
  delete legacyData.id;
  const signature = `${index}\0${JSON.stringify(legacyData)}`;
  return `legacy-cycle-${crypto.createHash('sha256').update(signature).digest('hex').slice(0, 24)}`;
}

async function readCyclesFromGitHub(){
  const response = await githubRequest('GET', undefined, GITHUB_CYCLES_FILE_URL);
  if(response.status === 404) return {cycles:[], sha:null};
  if(!response.ok) throw githubApiError(response.status);

  try{
    const file = await response.json();
    if(file.encoding !== 'base64' || typeof file.content !== 'string' || typeof file.sha !== 'string'){
      throw new Error('Invalid file response');
    }
    const content = Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
    const cycles = JSON.parse(content);
    if(!Array.isArray(cycles) || cycles.some(cycle=>!cycle || typeof cycle !== 'object' || Array.isArray(cycle))){
      throw new Error('Invalid cycles data');
    }
    const cyclesWithIds = cycles.map((cycle,index)=>({
      ...cycle,
      id:getCycleId(cycle,index),
      poemIds:Array.isArray(cycle.poemIds) ? cycle.poemIds.filter(id=>typeof id === 'string') : []
    }));
    return {cycles:cyclesWithIds, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_CYCLES_FILE');
  }
}

async function writeCyclesToGitHub(cycles, sha, message='Update cycles from admin panel'){
  const body = {
    message,
    content:Buffer.from(JSON.stringify(cycles, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body, GITHUB_CYCLES_FILE_URL);
  if(!response.ok) throw githubApiError(response.status);
}

async function mutateCyclesOnGitHub(mutate, message){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readCyclesFromGitHub();
    const cycles = mutate(current.cycles);

    try{
      await writeCyclesToGitHub(cycles, current.sha, message);
      return cycles;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_CYCLES_WRITE_CONFLICT');
}

function queueCycleMutation(mutate, message){
  return queueGitHubMutation(()=>mutateCyclesOnGitHub(mutate, message)).then(result=>{
    invalidatePublishedImageCache('cycles');
    return result;
  });
}

function getProseId(entry,index){
  if(typeof entry.id === 'string' && entry.id) return entry.id;
  const legacyData = {...entry};
  delete legacyData.id;
  const signature = `${index}\0${JSON.stringify(legacyData)}`;
  return `legacy-prose-${crypto.createHash('sha256').update(signature).digest('hex').slice(0, 24)}`;
}

async function readProseFromGitHub(){
  const response = await githubRequest('GET', undefined, GITHUB_PROSE_FILE_URL);
  if(response.status === 404) return {prose:[], sha:null};
  if(!response.ok) throw githubApiError(response.status);

  try{
    const file = await response.json();
    if(file.encoding !== 'base64' || typeof file.content !== 'string' || typeof file.sha !== 'string'){
      throw new Error('Invalid file response');
    }
    const content = Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
    const prose = JSON.parse(content);
    if(!Array.isArray(prose) || prose.some(entry=>!entry || typeof entry !== 'object' || Array.isArray(entry))){
      throw new Error('Invalid prose data');
    }
    const proseWithIds = prose.map((entry,index)=>({...entry,id:getProseId(entry,index)}));
    return {prose:proseWithIds, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_PROSE_FILE');
  }
}

async function writeProseToGitHub(prose, sha, message='Update prose from admin panel'){
  const body = {
    message,
    content:Buffer.from(JSON.stringify(prose, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body, GITHUB_PROSE_FILE_URL);
  if(!response.ok) throw githubApiError(response.status);
}

async function mutateProseOnGitHub(mutate, message){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readProseFromGitHub();
    const prose = mutate(current.prose);

    try{
      await writeProseToGitHub(prose, current.sha, message);
      return prose;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_PROSE_WRITE_CONFLICT');
}

function queueProseMutation(mutate, message){
  return queueGitHubMutation(()=>mutateProseOnGitHub(mutate, message)).then(result=>{
    invalidatePublishedImageCache('prose');
    return result;
  });
}

function validateProse(input){
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const type = input.type;
  const description = typeof input.description === 'string' ? input.description.trim() : '';
  const text = typeof input.text === 'string' ? input.text.trim() : '';
  const status = input.status === undefined ? 'published' : input.status;
  const date = typeof input.date === 'string' ? input.date.trim() : '';
  const image = typeof input.image === 'string' ? input.image.trim() : '';
  const imageCaption = typeof input.imageCaption === 'string' ? input.imageCaption.trim() : '';
  const imageSettings = validateImageSettings(input,type === 'chapter' ? 'chapter' : 'prose');
  const imageMetadata = validateImageMetadata(input);

  if(!title) return {error:'Название произведения обязательно'};
  if(title.length > 300 || description.length > 10000 || text.length > 1000000) return {error:'Название, описание или текст слишком длинные'};
  if(!['story','novel','chapter'].includes(type)) return {error:'Неизвестный тип произведения'};
  if(status !== 'published' && status !== 'draft') return {error:'Неизвестный статус произведения'};
  if(date){
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return {error:'Укажите корректную дату'};
    const parsedDate = new Date(date + 'T00:00:00.000Z');
    if(Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0,10) !== date) return {error:'Укажите корректную дату'};
  }
  const hasUnsupportedScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(image) && !image.startsWith('http://') && !image.startsWith('https://');
  if(image.length > 2048 || imageCaption.length > 500) return {error:'Ссылка или подпись к иллюстрации слишком длинная'};
  if(imageSettings.error) return imageSettings;
  if(imageMetadata.error) return imageMetadata;
  if(image && (hasUnsupportedScheme || !(image.startsWith('http://') || image.startsWith('https://') || image.startsWith('/') || /^[a-zA-Z0-9._-]/.test(image)))) return {error:'Укажите ссылку или путь к изображению'};

  return {prose:{title,type,description,text,status,date,image,imageCaption,...imageSettings.settings,...imageMetadata}};
}

function sendProseGitHubError(res,error,action){
  if(error.code === 'PROSE_NOT_FOUND'){
    sendJson(res,404,{error:'Произведение не найдено'});
    return;
  }
  if(error.code === 'GITHUB_TOKEN_MISSING'){
    sendJson(res,503,{error:'Хранилище произведений не настроено'});
    return;
  }
  if(error.status) console.error(`GitHub prose ${action} failed with status ${error.status}`);
  else console.error(`GitHub prose ${action} failed`);
  sendJson(res,502,{error:action === 'read' ? 'Не удалось загрузить произведения' : 'Не удалось сохранить произведение'});
}

function sendProseMutationError(res,error){
  sendProseGitHubError(res,error,'write');
}

async function removePoemReferencesFromCycles(poemId){
  let current = await readCyclesFromGitHub();

  for(let attempt=0;attempt<3;attempt++){
    const removedReferences = current.cycles
      .map((cycle,index)=>({
        cycleId:getCycleId(cycle,index),
        positions:(cycle.poemIds || []).reduce((positions,id,index)=>{
          if(id === poemId) positions.push(index);
          return positions;
        },[])
      }))
      .filter(reference=>reference.positions.length > 0);

    if(!removedReferences.length) return {rollbackReferences:[]};

    const updatedCycles = current.cycles.map((cycle,index)=>{
      const cycleId = getCycleId(cycle,index);
      if(!removedReferences.some(reference=>reference.cycleId === cycleId)) return cycle;
      return {...cycle,poemIds:(cycle.poemIds || []).filter(id=>id !== poemId)};
    });

    try{
      await writeCyclesToGitHub(updatedCycles,current.sha,'Remove deleted poem from cycles');
      return {rollbackReferences:removedReferences};
    }catch(error){
      let latest;
      try{
        latest = await readCyclesFromGitHub();
      }catch{
        throw error;
      }
      if(!latest.cycles.some(cycle=>(cycle.poemIds || []).includes(poemId))){
        return {rollbackReferences:[]};
      }
      if((error.status === 409 || error.status === 422) && attempt < 2){
        current = latest;
        continue;
      }
      throw error;
    }
  }

  throw githubApiError(409,'GITHUB_CYCLE_CLEANUP_CONFLICT');
}

async function restorePoemReferencesToCycles(poemId,references){
  if(!references.length) return;

  for(let attempt=0;attempt<3;attempt++){
    const current = await readCyclesFromGitHub();
    let changed = false;
    const restoredCycles = current.cycles.map((cycle,index)=>{
      const reference = references.find(item=>item.cycleId === getCycleId(cycle,index));
      if(!reference || (cycle.poemIds || []).includes(poemId)) return cycle;

      const poemIds = [...(cycle.poemIds || [])];
      reference.positions.forEach(position=>poemIds.splice(Math.min(position,poemIds.length),0,poemId));
      changed = true;
      return {...cycle,poemIds};
    });

    if(!changed) return;

    try{
      await writeCyclesToGitHub(restoredCycles,current.sha,'Restore poem references after failed deletion');
      return;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409,'GITHUB_CYCLE_RESTORE_CONFLICT');
}

async function deletePoemWithCycleCleanup(poemId){
  const currentPoems = await readPoemsFromGitHub();
  const poemIndex = currentPoems.poems.findIndex((poem,index)=>getPoemId(poem,index) === poemId);
  if(poemIndex < 0){
    const error = new Error('Poem not found');
    error.code = 'POEM_NOT_FOUND';
    throw error;
  }

  const canonicalPoemId = getPoemId(currentPoems.poems[poemIndex],poemIndex);
  const {rollbackReferences} = await removePoemReferencesFromCycles(canonicalPoemId);
  const updatedPoems = currentPoems.poems.filter((_,index)=>index !== poemIndex);

  try{
    await writePoemsToGitHub(updatedPoems,currentPoems.sha,'Delete poem from admin panel');
    return updatedPoems;
  }catch(error){
    let latestPoems;
    try{
      latestPoems = await readPoemsFromGitHub();
    }catch{
      throw error;
    }

    const poemStillExists = latestPoems.poems.some((poem,index)=>getPoemId(poem,index) === canonicalPoemId);
    if(!poemStillExists) return latestPoems.poems;

    await restorePoemReferencesToCycles(canonicalPoemId,rollbackReferences);
    throw error;
  }
}

function queuePoemDeletionWithCycleCleanup(poemId){
  return queueGitHubMutation(()=>deletePoemWithCycleCleanup(poemId)).then(result=>{
    invalidatePublishedImageCache('poems','cycles');
    return result;
  });
}

function validateCycle(input, existingPoemIds){
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const description = typeof input.description === 'string' ? input.description.trim() : '';
  const status = input.status === undefined ? 'published' : input.status;
  const imageValue = typeof input.image === 'string' ? input.image : input.cover;
  const cover = typeof imageValue === 'string' ? imageValue.trim() : '';
  const imageCaption = typeof input.imageCaption === 'string' ? input.imageCaption.trim() : '';
  const poemIds = input.poemIds;
  const imageSettings = validateImageSettings(input,'cycle');
  const imageMetadata = validateImageMetadata(input);

  if(!title) return {error:'Название цикла обязательно'};
  if(title.length > 300 || description.length > 10000) return {error:'Название или описание цикла слишком длинные'};
  if(status !== 'published' && status !== 'draft') return {error:'Неизвестный статус цикла'};
  if(imageCaption.length > 500) return {error:'Подпись к иллюстрации слишком длинная'};
  if(imageSettings.error) return imageSettings;
  if(imageMetadata.error) return imageMetadata;
  const hasUnsupportedScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cover) && !cover.startsWith('http://') && !cover.startsWith('https://');
  if(cover.length > 2048 || (cover && (hasUnsupportedScheme || !(cover.startsWith('http://') || cover.startsWith('https://') || cover.startsWith('/') || /^[a-zA-Z0-9._-]/.test(cover))))) return {error:'Укажите ссылку или путь к обложке'};
  if(!Array.isArray(poemIds) || poemIds.length > 500 || poemIds.some(id=>typeof id !== 'string' || !id)) return {error:'Неверный список стихотворений'};
  if(new Set(poemIds).size !== poemIds.length) return {error:'Стихотворение уже добавлено в цикл'};
  if(poemIds.some(id=>!existingPoemIds.has(id))) return {error:'В цикле могут быть только существующие стихотворения'};

  return {cycle:{title,description,status,cover,image:cover,imageCaption,poemIds:[...poemIds],...imageSettings.settings,...imageMetadata}};
}

function sendCycleMutationError(res, error){
  if(error.code === 'CYCLE_NOT_FOUND'){
    sendJson(res, 404, {error:'Цикл не найден'});
    return;
  }
  sendGitHubError(res, error, 'write');
}

function sendGitHubError(res, error, action){
  if(error.code === 'GITHUB_TOKEN_MISSING'){
    sendJson(res, 503, {error:'Хранилище стихотворений не настроено'});
    return;
  }

  if(error.status) console.error(`GitHub ${action} failed with status ${error.status}`);
  else console.error(`GitHub ${action} failed`);
  sendJson(res, 502, {error:action === 'read' ? 'Не удалось загрузить стихотворения' : 'Не удалось сохранить стихотворение'});
}

function readRequestBody(req,maxBytes=1024 * 1024){
  return new Promise((resolve, reject)=>{
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk=>{
      body += chunk;
      if(Buffer.byteLength(body,'utf8') > maxBytes){
        reject(new Error('Request body is too large'));
        req.destroy();
      }
    });
    req.on('end', ()=>resolve(body));
    req.on('error', reject);
  });
}

const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#17171c">
<title>Посмертие Ринны — Архив</title>
<style>
:root{
  color-scheme:dark;
  --ink:#f5eff0;
  --muted:#ae9ca0;
  --dim:#79666b;
  --line:#45141f;
  --nav:#0a0709;
  --nav-hover:#241015;
  --canvas:#0d0709;
  --panel:#160c10;
  --panel-soft:#1c0d12;
  --accent:#ee2349;
  --accent-bright:#ff365a;
  --accent-dark:#3a0d18;
  --success:#a0ae8b;
  --danger:#ff7180;
}
*{box-sizing:border-box}
body{
  position:relative;
  margin:0;
  background:
    radial-gradient(ellipse at 78% 0%,#310c1938 0,transparent 38%),
    radial-gradient(ellipse at 10% 38%,#2109102c 0,transparent 45%),
    var(--canvas);
  color:var(--ink);
  font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:15px;
  line-height:1.5;
}
body:before{
  content:"";
  position:fixed;
  z-index:0;
  inset:0;
  pointer-events:none;
  opacity:.15;
  background:
    linear-gradient(90deg,transparent 0,transparent 79px,#8d1a321f 80px,transparent 81px),
    linear-gradient(0deg,transparent 0,transparent 79px,#8d1a3212 80px,transparent 81px);
  background-size:80px 80px;
}
button,input,textarea{font:inherit}
button{cursor:pointer}
.login,.app{position:relative;z-index:1}
.login{
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:24px;
  background:radial-gradient(ellipse at 50% 0,#3a101c88 0,transparent 56%);
}
.login-box{
  width:min(100%,430px);
  padding:38px;
  background:#130a0e;
  border:1px solid #6a1c2d;
  border-radius:3px;
  box-shadow:0 28px 90px #0009,0 0 55px #5c0c2018;
}
.login-mark,.brand-mark{
  display:grid;
  place-items:center;
  width:42px;
  height:42px;
  border:1px solid #8d2038;
  border-radius:2px;
  color:var(--accent-bright);
  font-family:Georgia,"Times New Roman",serif;
  font-size:23px;
}
.login-box .login-mark{margin-bottom:22px}
.logo{font:700 29px Georgia,"Times New Roman",serif;letter-spacing:.01em}
.muted{color:var(--muted)}
.login .muted{margin:8px 0 28px}
label{display:block;color:#cbbdc0;font-size:13px;margin:18px 0 7px}
input,textarea{
  width:100%;
  background:#0b0709;
  color:#fff;
  border:1px solid #51202a;
  border-radius:2px;
  padding:13px 14px;
  outline:none;
  transition:border-color .16s,box-shadow .16s,background .16s;
}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 2px #ee234922;background:#10080b}
.btn{
  border:1px solid var(--accent);
  border-radius:2px;
  padding:12px 17px;
  background:var(--accent);
  color:#fff7f8;
  font-weight:750;
  letter-spacing:.015em;
  transition:background .16s,border-color .16s,color .16s,transform .16s,box-shadow .16s;
}
.btn:hover{background:var(--accent-bright);border-color:var(--accent-bright);transform:translateY(-1px);box-shadow:0 5px 18px #ee23492e}
.btn:disabled{opacity:.55;cursor:wait;transform:none;box-shadow:none}
.login .btn{width:100%;margin-top:22px}
.error{color:#ff9ca7;margin-top:14px;display:none}
.app{display:none;min-height:100vh}
.sidebar{
  position:fixed;
  z-index:5;
  inset:0 auto 0 0;
  width:254px;
  display:flex;
  flex-direction:column;
  padding:26px 17px 18px;
  background:linear-gradient(180deg,#0d080a 0,#0a0709 100%);
  border-right:1px solid #571827;
}
.brand{display:flex;align-items:center;gap:12px;padding:1px 9px 30px}
.brand-mark{flex:0 0 42px}
.brand-name{font:700 17px Georgia,"Times New Roman",serif;letter-spacing:.015em}
.brand-caption{color:#8d6a73;font-size:10px;letter-spacing:.17em;text-transform:uppercase;margin-top:3px}
.nav{display:grid;gap:5px}
.nav-link{
  position:relative;
  display:flex;
  align-items:center;
  gap:13px;
  width:100%;
  padding:11px 12px;
  color:#a9969b;
  text-align:left;
  background:transparent;
  border:1px solid transparent;
  border-radius:2px;
  transition:background .16s,color .16s,border-color .16s;
}
.nav-link:hover{background:#210d13;color:#fff;border-color:#4e1624}
.nav-link.active{background:linear-gradient(90deg,#3a101b,#200d12);border-color:#711d31;color:#fff}
.nav-link.active:before{content:"";position:absolute;inset:7px auto 7px -1px;width:2px;background:var(--accent)}
.nav-icon{width:20px;text-align:center;color:#a15a69;font-size:17px}
.nav-link:hover .nav-icon,.nav-link.active .nav-icon{color:var(--accent-bright)}
.sidebar-bottom{margin-top:auto}
.sidebar-note{margin:0 8px 14px;padding:13px 11px;border-top:1px solid #4a1724;color:#866e74;font:italic 13px Georgia,"Times New Roman",serif}
.logout{color:#c9828f}
.logout:hover{background:#300d18;color:#ffdfe4;border-color:#83223a}
.content{margin-left:254px;max-width:1500px;padding:30px 42px 52px}
.topbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  min-height:53px;
  margin-bottom:34px;
  padding-bottom:19px;
  border-bottom:1px solid #4e1725;
}
.crumb{color:#c4adb2;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.crumb:before{
  content:"ARCHIVE / PERSONAL / 2026";
  display:block;
  margin-bottom:5px;
  color:#a93a51;
  font-size:9px;
  font-weight:700;
  letter-spacing:.2em;
}
.topbar-user{display:flex;align-items:center;gap:10px;color:#c9b8bc;font-size:12px;letter-spacing:.04em}
.avatar{display:grid;place-items:center;width:34px;height:34px;border:1px solid #792039;border-radius:2px;color:var(--accent-bright);font-family:Georgia,serif}
.section{display:none;animation:appear .22s ease}
.section.active{display:block}
@keyframes appear{from{opacity:.3;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.page-heading{margin-bottom:25px}
h1{margin:0;font:800 clamp(30px,3.2vw,43px)/1.08 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.045em}
.subtitle{margin-top:9px;color:#a9959a;font:italic 16px Georgia,"Times New Roman",serif}
.eyebrow{margin-bottom:10px;color:#d24660;font-size:10px;font-weight:750;letter-spacing:.2em;text-transform:uppercase}
#dashboard .hero .eyebrow:before{
  content:"00 / ARCHIVE";
  display:block;
  margin-bottom:10px;
  color:#c44159;
  font-size:9px;
  letter-spacing:.2em;
}
#poems .page-heading .eyebrow:before{content:"01 / POETRY  ·  "}
#cycles .page-heading .eyebrow:before{content:"02 / CYCLES  ·  "}
#prose .page-heading .eyebrow:before{content:"03 / PROSE  ·  "}
#settings .page-heading .eyebrow:before{content:"04 / SETTINGS  ·  "}
.hero{
  position:relative;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:24px;
  overflow:hidden;
  padding:34px 36px;
  border:1px solid #702033;
  border-radius:2px;
  background:linear-gradient(112deg,#260b13 0,#1b0a10 55%,#16090e 100%);
  margin-bottom:20px;
  box-shadow:inset 0 1px #e43a581c,0 16px 38px #0003;
}
.hero:before{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:linear-gradient(180deg,transparent,var(--accent),transparent)}
.hero-content{position:relative;z-index:1;flex:1;min-width:0}
.hero-mascot{position:relative;z-index:1;display:block;flex:0 0 auto;width:auto;height:128px;max-width:25%;object-fit:contain;opacity:.72;filter:saturate(.72) brightness(.78);pointer-events:none;user-select:none}
.hero h1{position:relative;z-index:1}
.hero p{position:relative;z-index:1;max-width:600px;margin:12px 0 22px;color:#c6b3b7;font:italic 16px/1.65 Georgia,"Times New Roman",serif}
.quick-actions{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:9px}
.btn-secondary{
  padding:10px 14px;
  background:#11080c;
  border:1px solid #662034;
  border-radius:2px;
  color:#e7d9dc;
  font-weight:650;
  transition:background .16s,border-color .16s,color .16s,transform .16s;
}
.btn-secondary:hover{background:#3b0e1b;border-color:var(--accent);color:#fff;transform:translateY(-1px)}
.btn-secondary:after{content:" ↗";color:#c5405b}
.btn-secondary .plus{color:var(--accent-bright);margin-right:7px}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:20px}
.stat-card,.panel,.storage-card{position:relative;background:linear-gradient(145deg,#1a0d12,#130a0e);border:1px solid #431722;border-radius:2px;box-shadow:0 10px 26px #0002}
.stat-card:before,.panel:before{content:"";position:absolute;top:-1px;left:18px;width:38px;height:1px;background:#b52a46}
.stat-card{padding:19px 21px;transition:border-color .18s,transform .18s,background .18s}
.stat-card:hover{transform:translateY(-2px);border-color:#84233b;background:#210d13}
.stat-top{display:flex;align-items:center;justify-content:space-between;color:#b7a5aa;font-size:12px;letter-spacing:.13em;text-transform:uppercase}
.stat-symbol{color:#d33755;font-size:18px}
.stat-number{margin-top:9px;color:#fff5f6;font:700 36px Georgia,"Times New Roman",serif}
.stat-foot{margin-top:2px;color:#806c72;font-size:11px;letter-spacing:.04em}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(250px,.85fr);gap:16px}
.panel{padding:21px 22px}
.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}
.panel h2{margin:0;color:#f2e8ea;font:600 21px Georgia,"Times New Roman",serif}
.panel-kicker{color:#946c75;font-size:10px;letter-spacing:.15em;text-transform:uppercase}
.recent-list{display:grid}
.recent-entry{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:13px 0;border-bottom:1px solid #3a151f;transition:padding .16s}
.recent-entry:hover{padding-left:5px}
.recent-entry:last-child{border-bottom:0}
.recent-icon{display:grid;place-items:center;width:32px;height:32px;border:1px solid #642033;border-radius:2px;background:#230c13;color:#ee3656}
.recent-title{overflow:hidden;color:#f1e7e9;text-overflow:ellipsis;white-space:nowrap;font-weight:650}
.recent-copy{display:-webkit-box;overflow:hidden;margin-top:3px;color:#a08d92;font:13px/1.45 Georgia,"Times New Roman",serif;-webkit-box-orient:vertical;-webkit-line-clamp:2}
.empty-note{padding:18px 0;color:#9a858b;font:italic 14px Georgia,"Times New Roman",serif}
.draft-empty{padding:14px 0 8px}
.draft-mark{display:grid;place-items:center;width:40px;height:40px;margin-bottom:12px;border:1px solid #5b1a2c;border-radius:2px;color:#dc3655;font-size:18px}
.draft-empty p{margin:5px 0 0;color:#9c888e;font:italic 13px Georgia,"Times New Roman",serif}
.storage-card{display:flex;align-items:flex-start;gap:13px;margin-top:15px;padding:16px;border-color:#4a1925}
.status-dot{flex:0 0 9px;width:9px;height:9px;margin-top:6px;border-radius:50%;background:#aa7f83;box-shadow:0 0 0 4px #aa7f8318}
.status-dot.online{background:var(--success);box-shadow:0 0 0 4px #a0ae8b1b}
.status-dot.offline{background:var(--danger);box-shadow:0 0 0 4px #ff71801b}
.storage-title{font-size:13px;font-weight:700}
.storage-copy{margin-top:3px;color:#9a858b;font-size:11px}
.section-top{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:22px}
.section-top .page-heading{margin:0}
.add{white-space:nowrap}
.add:after{content:"  →";font-size:15px}
.poem-panel{padding:22px}
#poem-form{max-width:780px;margin-bottom:21px;padding-bottom:21px;border-bottom:1px solid #592031}
#poem-form textarea{resize:vertical;min-height:160px}
.editor-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
.editor-field-wide{grid-column:1/-1}
.editor-fields select{width:100%;padding:13px 14px;background:#0b0709;color:#f5eff0;border:1px solid #51202a;border-radius:2px}
.editor-fields select:focus{outline:2px solid #ee234922;border-color:var(--accent)}
.optional{margin-left:5px;color:#927d83;font-size:11px}
.editor-actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:22px}
.editor-actions .btn{width:auto}
.btn-danger{padding:10px 14px;background:#1c0a0f;border:1px solid #772036;border-radius:2px;color:#ed8797;font-weight:650}
.btn-danger:hover{background:#3b0d18;border-color:#e33454;color:#fff}
.poem-item-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.poem-item-date{margin-top:5px;color:#987d84;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.poem-status{display:inline-block;padding:4px 8px;border:1px solid #783047;color:#f18ba0;font-size:10px;letter-spacing:.12em;text-transform:uppercase;white-space:nowrap}
.poem-status.draft{border-color:#69502a;color:#d8b777}
.poem-snippet{display:-webkit-box;overflow:hidden;margin-top:10px;color:#b4a1a6;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap;-webkit-box-orient:vertical;-webkit-line-clamp:2}
.poem-item-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.poem-item-actions .btn-secondary,.poem-item-actions .btn-danger{padding:7px 10px;font-size:12px}
.poem-item-actions .btn-secondary:after{content:""}
.poem-filter-bar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:8px;padding-bottom:15px;border-bottom:1px solid #401722}
.poem-cycle-filter{display:flex;flex-wrap:wrap;gap:7px}
.poem-cycle-filter button{padding:7px 11px;border:1px solid #54202c;border-radius:2px;background:#10080b;color:#ae969c;font-size:11px;transition:background .15s,border-color .15s,color .15s}
.poem-cycle-filter button:hover,.poem-cycle-filter button.active{border-color:#a62a45;background:#310e18;color:#fff}
.poem-filter-count{color:#8d747b;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.prose-filter-bar{display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:8px;padding-bottom:15px;border-bottom:1px solid #401722}
.prose-search-label{margin:0 0 0 auto;color:#8d747b;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.prose-search{width:min(100%,240px);padding:8px 10px;font-size:12px}
.prose-list{display:grid}
.prose-card{padding:18px 0;border-bottom:1px solid #401722}
.prose-card:last-child{border-bottom:0}
.prose-card-type{margin:0 0 4px;color:#c54a62;font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}
.prose-card .poem-item-date{margin-top:5px}
.prose-empty{padding:22px 0;color:#a08a91;font:italic 15px Georgia,"Times New Roman",serif}
.prose-preview-description{margin:-12px 0 24px;color:#c9b5bb;font:italic 16px/1.7 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.poem-cycle-info{margin-top:8px;color:#97757d;font-size:11px;letter-spacing:.06em}
.poem-cycle-info.has-cycles{color:#d44c65}
.poem-cycle-editor{margin-top:18px;padding:14px 15px;border:1px solid #421722;background:#11080c}
.poem-cycle-editor-title{margin-bottom:8px;color:#d64c65;font-size:10px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
.poem-editor-cycle{padding:5px 0;color:#e2cdd2;font:14px Georgia,"Times New Roman",serif}
.poem-editor-cycle + .poem-editor-cycle{border-top:1px solid #35131b}
.poem-editor-cycle-note{color:#947d83;font:italic 12px Georgia,"Times New Roman",serif}
.preview-overlay{position:fixed;z-index:20;inset:0;display:grid;place-items:center;padding:24px;background:#050305e8;backdrop-filter:blur(5px)}
.preview-overlay[hidden]{display:none}
.preview-dialog{width:min(100%,850px);max-height:min(90vh,900px);overflow:auto;background:#10080b;border:1px solid #762038;box-shadow:0 24px 100px #000b}
.preview-toolbar{position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#10080bf2;border-bottom:1px solid #501725;color:#c54a62;font-size:10px;font-weight:700;letter-spacing:.18em}
.preview-poem{position:relative;max-width:700px;margin:0 auto;padding:clamp(28px,7vw,76px) clamp(22px,7vw,72px) 64px}
.preview-poem:before{content:"";position:absolute;top:28px;left:0;width:28px;height:1px;background:var(--accent)}
.preview-index{color:#ac4057;font-size:9px;font-weight:700;letter-spacing:.2em}
.preview-date{margin-top:24px;color:#a78e94;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.preview-poem h2{overflow-wrap:anywhere;margin:12px 0 27px;color:#fff1f3;font:700 clamp(30px,5vw,48px)/1.12 Georgia,"Times New Roman",serif}
.preview-body{color:#e3d5d9;font:18px/1.9 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.preview-figure{position:relative;display:block;clear:both;box-sizing:border-box;width:100%;max-width:700px;overflow:hidden;isolation:isolate;margin:36px 0 0;background:#0b0709}
.illustration-frame{position:relative;display:block;box-sizing:border-box;width:100%;height:auto;overflow:hidden;isolation:isolate;container-type:inline-size;border:0;background:#0b0709}
.illustration-frame>img{position:absolute;z-index:0;inset:0;display:block;width:100%;height:100%;margin:0;object-fit:contain;transform-origin:center center}
.illustration-frame.archive-frame{border-color:transparent;box-shadow:none}
.illustration-frame.archive-frame:before{position:absolute;z-index:3;inset:var(--image-inset-top,0%) var(--image-inset-right,0%) var(--image-inset-bottom,0%) var(--image-inset-left,0%);box-sizing:border-box;content:"";border:1px solid #762038;box-shadow:inset 0 0 0 1px #ed29401c;pointer-events:none}
.image-darkening-layer,.image-effect-preview-overlay{position:absolute;z-index:1;inset:var(--image-inset-top,0%) var(--image-inset-right,0%) var(--image-inset-bottom,0%) var(--image-inset-left,0%);pointer-events:none;transition:background .2s}
.image-darkening-layer[hidden]{display:none}
.archive-overlay{position:absolute;z-index:2;inset:var(--image-inset-top,0%) var(--image-inset-right,0%) var(--image-inset-bottom,0%) var(--image-inset-left,0%);overflow:hidden;pointer-events:none;color:#f5eff0;font:700 clamp(6px,2.2cqw,9px)/1.35 Arial,sans-serif;letter-spacing:.12em;text-transform:uppercase;user-select:none;-webkit-user-select:none}
.archive-overlay[hidden]{display:none}
.archive-grid{position:absolute;z-index:1;inset:0;background:repeating-linear-gradient(0deg,transparent 0 5px,#fff1 5px 6px),repeating-linear-gradient(90deg,transparent 0 44px,#ee234912 44px 45px),linear-gradient(90deg,transparent 8%,#ee23491c 8.1%,transparent 8.2%,transparent 91%,#ee23491c 91.1%,transparent 91.2%)}
.archive-outline{position:absolute;z-index:2;inset:7px;border:1px solid #a72b441c}
.archive-outline:before,.archive-outline:after{position:absolute;content:"";width:22px;height:22px;border-color:#ec3150;border-style:solid;opacity:.72}
.archive-outline:before{top:-1px;left:-1px;border-width:1px 0 0 1px}
.archive-outline:after{right:-1px;bottom:-1px;border-width:0 1px 1px 0}
.archive-visual-label,.archive-corner-label{position:absolute;z-index:3;max-width:44%;overflow:hidden;padding:clamp(3px,1.5cqw,7px);background:#10080bc9;text-overflow:ellipsis;white-space:nowrap}
.archive-visual-label{bottom:calc(var(--image-inset-bottom,0%) + clamp(5px,1.5cqw,12px));left:calc(var(--image-inset-left,0%) + clamp(5px,1.5cqw,12px));border-left:1px solid #ee2349}
.archive-corner-label{top:calc(var(--image-inset-top,0%) + clamp(5px,1.5cqw,12px));right:calc(var(--image-inset-right,0%) + clamp(5px,1.5cqw,12px));color:#ef8191;text-align:right}
.archive-corner-label[hidden]{display:none}
.archive-meta-caption{display:block;box-sizing:border-box;width:100%;margin:0;padding:8px 10px;border-left:1px solid #ee2349;background:linear-gradient(90deg,#10080bd9,#10080b88 80%,transparent);color:#eee0e3;text-align:left;font:700 8px/1.6 Arial,sans-serif;letter-spacing:.1em;overflow-wrap:anywhere}
.preview-figure figcaption .archive-meta-caption,.cycle-preview-figure figcaption .archive-meta-caption{color:#eee0e3;text-align:left;font:700 8px/1.6 Arial,sans-serif;letter-spacing:.1em}
.archive-meta-caption[hidden]{display:none}
.image-effect-preview-meta{grid-column:1/-1;margin-top:-8px}
.preview-figure figcaption,.cycle-preview-figure figcaption{position:relative;display:flex;flex-direction:column;gap:8px;margin:0;padding:10px 0 0;border:0;color:#a58a91;text-align:center;font:italic 13px Georgia,"Times New Roman",serif;overflow-wrap:anywhere}
.preview-figure figcaption[hidden],.cycle-preview-figure figcaption[hidden]{display:none}
.image-caption-text{display:block;padding:2px 12px 8px}
.cycle-preview-figure{position:relative;display:block;clear:both;width:100%;max-width:760px;overflow:hidden;margin:0 auto 30px;isolation:isolate;background:#0b0709}
.cycle-preview-content h2{overflow-wrap:anywhere}
.cycle-preview-figure .illustration-frame{height:auto}
.preview-status{margin-top:26px;color:#a83b53;font-size:9px;font-weight:700;letter-spacing:.2em;text-transform:uppercase}
.image-editor{padding:15px;border:1px solid #421722;background:linear-gradient(145deg,#170b10,#10080b)}
.image-editor-layout{display:grid;grid-template-columns:minmax(150px,220px) minmax(0,1fr);gap:16px}
.image-editor-preview{position:relative;display:grid;place-items:center;width:100%;height:auto;min-height:0;overflow:hidden;isolation:isolate;container-type:inline-size;box-shadow:inset 0 0 0 1px #5a1c2d;background:#0b0709}
.image-editor-preview[data-empty="true"]{height:180px}
.image-editor-preview img{position:absolute;z-index:0;inset:0;width:100%;height:100%;min-height:0;object-fit:contain;transform-origin:center center}
.image-editor-preview img,.image-effect-preview-frame img,.preview-figure img{-webkit-user-drag:none;user-select:none}
.image-editor-preview img[hidden]{display:none}
.image-editor-placeholder{position:relative;z-index:5;padding:12px;color:#806b72;text-align:center;font:italic 12px/1.5 Georgia,"Times New Roman",serif}
.image-editor-controls{min-width:0}
.image-editor-controls label:first-child{margin-top:0}
.image-editor-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:11px}
.image-editor-actions button{padding:8px 11px;font-size:12px}
.image-editor-actions .btn-secondary:after{content:""}
.image-editor-meta{display:flex;flex-wrap:wrap;gap:8px 14px;margin-top:9px;color:#987d84;font-size:10px;letter-spacing:.04em}
.image-editor-error{display:none;margin-top:8px;color:#ff9ca7;font-size:12px}
.image-editor-error.visible{display:block}
.image-effect-button{margin-top:12px}
.image-effect-button:after{content:""}
.image-effect-dialog{width:min(100%,920px);max-height:min(92vh,1000px);overflow:auto;background:#10080b;border:1px solid #762038;box-shadow:0 24px 100px #000b}
.image-effect-content{padding:22px}
.image-effect-content .panel-heading{justify-content:flex-start}
.image-effect-content .panel-heading h2{margin-top:3px}
.image-effect-preview-frame{position:relative;box-sizing:border-box;width:100%;height:auto;min-height:0;overflow:hidden;isolation:isolate;container-type:inline-size;box-shadow:inset 0 0 0 1px #682035;background:#0a0608}
.image-effect-preview-frame[data-empty="true"]{height:280px}
.image-effect-preview-frame img{position:absolute;z-index:0;inset:0;width:100%;height:100%;object-fit:contain;transform-origin:center center;transition:opacity .35s,transform .35s,filter .35s,box-shadow .35s}
.image-effect-preview-frame img[hidden]{display:none}
.image-effect-preview-overlay{z-index:1}
.image-effect-preview-empty{position:absolute;z-index:5;inset:0;display:grid;place-items:center;color:#806b72;font:italic 14px Georgia,"Times New Roman",serif}
.image-effect-preview-empty[hidden]{display:none}
.image-watermark-layer,.image-effect-watermark{position:absolute;z-index:4;max-width:70%;pointer-events:none;color:#fff;font:700 clamp(8px,4cqw,19px)/1.2 Georgia,"Times New Roman",serif;letter-spacing:.03em;text-shadow:0 2px 5px #000,0 0 2px #000;user-select:none;-webkit-user-select:none}
.image-watermark-layer[data-position="top-left"],.image-effect-watermark[data-position="top-left"]{top:calc(var(--image-inset-top,0%) + clamp(5px,1.7cqw,12px));left:calc(var(--image-inset-left,0%) + clamp(5px,1.7cqw,12px))}
.image-watermark-layer[data-position="top-right"],.image-effect-watermark[data-position="top-right"]{top:calc(var(--image-inset-top,0%) + clamp(5px,1.7cqw,12px));right:calc(var(--image-inset-right,0%) + clamp(5px,1.7cqw,12px))}
.image-watermark-layer[data-position="center"],.image-effect-watermark[data-position="center"]{top:calc(var(--image-inset-top,0%) + (100% - var(--image-inset-top,0%) - var(--image-inset-bottom,0%)) / 2);left:calc(var(--image-inset-left,0%) + (100% - var(--image-inset-left,0%) - var(--image-inset-right,0%)) / 2);transform:translate(-50%,-50%)}
.image-watermark-layer[data-position="bottom-left"],.image-effect-watermark[data-position="bottom-left"]{bottom:calc(var(--image-inset-bottom,0%) + clamp(5px,1.7cqw,12px));left:calc(var(--image-inset-left,0%) + clamp(5px,1.7cqw,12px))}
.image-watermark-layer[data-position="bottom-right"],.image-effect-watermark[data-position="bottom-right"]{bottom:calc(var(--image-inset-bottom,0%) + clamp(5px,1.7cqw,12px));right:calc(var(--image-inset-right,0%) + clamp(5px,1.7cqw,12px))}
.image-hover-toggle{margin-top:9px;padding:7px 10px;font-size:11px}
.image-hover-toggle:after{content:""}
.image-hover-toggle.active{border-color:#bf3150;background:#35101b;color:#fff}
.image-effect-controls{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px;margin-top:8px}
.image-effect-controls .archive-settings-heading,.image-effect-controls .archive-live-preview-label,.image-effect-controls .archive-preview-frame{grid-column:1/-1}
.archive-settings-heading{margin-top:15px;padding-top:14px;border-top:1px solid #602033}
.archive-live-preview-label{margin-top:10px}
.archive-preview-frame{width:100%;height:auto}
.archive-preview-frame>img{object-fit:contain}
.image-effect-controls select{width:100%;padding:12px;background:#0b0709;color:#f5eff0;border:1px solid #51202a;border-radius:2px}
.image-effect-controls select:focus{outline:2px solid #ee234922;border-color:var(--accent)}
.image-effect-controls input[type="range"]{padding:9px 0;border:0;background:transparent;accent-color:var(--accent)}
.image-effect-controls input[type="checkbox"]{width:auto;margin-right:7px;accent-color:var(--accent)}
.image-effect-controls output{float:right;color:#e78697;font-size:11px}
.image-effect-controls .editor-field-wide{grid-column:1/-1}
.cycle-picker{display:flex;align-items:stretch;gap:9px}
.cycle-picker select{flex:1;min-width:0;padding:11px 12px;background:#0b0709;color:#f5eff0;border:1px solid #51202a;border-radius:2px}
.cycle-picker button:disabled{opacity:.45;cursor:not-allowed}
.cycle-selection-heading{display:flex;justify-content:space-between;gap:12px;margin:22px 0 8px;color:#f0e4e7;font-size:13px;font-weight:700}
.cycle-selection-heading span{color:#90777e;font-size:11px;font-weight:400}
.cycle-selected-list{display:grid;gap:7px}
.cycle-selected-row{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:10px;padding:9px 10px;border:1px solid #401722;background:#12090d}
.cycle-order{color:#a83d55;font:11px Georgia,serif;text-align:center}
.cycle-poem-name{overflow:hidden;color:#e9dce0;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.cycle-poem-missing{color:#d77b88}
.cycle-order-actions{display:flex;gap:5px}
.cycle-order-actions button{width:29px;height:29px;padding:0;border:1px solid #612034;border-radius:2px;background:#1a0b10;color:#dbaab3}
.cycle-order-actions button:hover:not(:disabled){border-color:var(--accent);background:#3b0e1b;color:#fff}
.cycle-order-actions button:disabled{opacity:.35;cursor:not-allowed}
.cycle-list{display:grid;gap:12px}
.cycle-card{display:grid;grid-template-columns:100px minmax(0,1fr);gap:17px;padding:17px 0;border-bottom:1px solid #401722}
.cycle-card:last-child{border-bottom:0}
.cycle-card-cover{width:100px;height:100px;object-fit:cover;border:1px solid #672034;background:#0c0709}
.cycle-card-cover[hidden]{display:none}
.cycle-card-body{min-width:0}
.cycle-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.cycle-card-description{margin:8px 0 0;color:#aa969c;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.cycle-card-count{margin-top:8px;color:#946c75;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.cycle-card-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:13px}
.cycle-card-actions button{padding:7px 10px;font-size:12px}
.cycle-card-actions .btn-secondary:after{content:""}
.cycle-empty{padding:20px 0;color:#a08a91;font:italic 15px Georgia,"Times New Roman",serif}
.cycle-preview-content{position:relative;max-width:760px;margin:0 auto;padding:clamp(28px,6vw,64px)}
.cycle-preview-cover[hidden]{display:none}
.cycle-preview-content h2{overflow-wrap:anywhere;margin:13px 0;color:#fff1f3;font:700 clamp(32px,5vw,50px)/1.1 Georgia,"Times New Roman",serif}
.cycle-preview-description{overflow-wrap:anywhere;color:#c9b5bb;font:italic 16px/1.7 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.cycle-preview-poems{display:grid;margin-top:30px;border-top:1px solid #501725}
.cycle-preview-poem{padding:16px 0;border-bottom:1px solid #501725}
.cycle-preview-poem strong{display:block;color:#f2e4e7;font:600 19px Georgia,"Times New Roman",serif}
.cycle-preview-poem p{margin:6px 0 0;color:#a9959a;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.poem-list .item{padding:18px 0;border-bottom:1px solid #401722}
.poem-list .item:last-child{border-bottom:0}
.item-title{margin-bottom:6px;color:#f4e9eb;font:600 21px Georgia,"Times New Roman",serif}
.item-meta{color:#b4a1a6;font:14px/1.65 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.item-meta.empty-copy{color:#927d83}
.placeholder-panel{max-width:820px}
.placeholder-glyph{display:grid;place-items:center;width:48px;height:48px;margin-bottom:15px;border:1px solid #76223a;border-radius:2px;color:var(--accent-bright);font:24px Georgia,serif}
.placeholder-panel p{max-width:590px;margin:8px 0 0;color:#aa969c;font:italic 15px/1.65 Georgia,"Times New Roman",serif}
.settings-row{display:flex;justify-content:space-between;gap:16px;padding:15px 0;border-bottom:1px solid #401722;color:#cbb9bd}
.settings-row:last-child{border-bottom:0}
.settings-value{color:#a77c85;font-family:Georgia,"Times New Roman",serif}
@media(max-width:1000px){
  .content{padding:27px 28px}
  .sidebar{width:225px}
  .content{margin-left:225px}
  .dashboard-grid{grid-template-columns:1fr}
  .brand-name{font-size:15px}
}
@media(max-width:700px){
  .sidebar{position:sticky;inset:0 0 auto;width:100%;padding:12px 14px 10px;border-right:0;border-bottom:1px solid #571827}
  .brand{padding:0 4px 12px}
  .brand-mark{width:34px;height:34px;flex-basis:34px;border-radius:2px;font-size:19px}
  .brand-caption{display:none}
  .nav{display:flex;gap:5px;overflow-x:auto;padding-bottom:2px}
  .nav-link{width:auto;flex:0 0 auto;padding:9px 10px;font-size:13px}
  .nav-icon{width:auto}
  .nav-link.logout{margin-left:auto}
  .sidebar-bottom{display:none}
  .content{margin-left:0;padding:22px 17px 40px}
  .topbar{margin-bottom:25px}
  .topbar-user span:last-child{display:none}
  .hero{padding:25px 22px;gap:14px}
  .hero-mascot{height:100px;max-width:24%}
  .editor-fields{grid-template-columns:1fr}
  .editor-field-wide{grid-column:auto}
  .image-editor-layout{grid-template-columns:1fr}
  .image-editor-preview[data-empty="true"]{height:180px}
  .image-effect-controls{grid-template-columns:1fr}
  .image-effect-controls .editor-field-wide{grid-column:auto}
  .image-effect-preview-frame[data-empty="true"]{height:210px}
  .cycle-picker{flex-direction:column}
  .stats{gap:9px}
  .stat-card{padding:15px 13px}
  .stat-top{align-items:flex-start;gap:5px;font-size:11px}
  .stat-number{font-size:29px}
  .stat-foot{font-size:10px}
  .section-top{align-items:flex-start;flex-direction:column}
  .add{width:auto}
  .poem-panel,.panel{padding:18px}
  .login-box{padding:29px 24px}
}
@media(max-width:480px){
  .hero{display:block;padding:22px 19px}
  .hero-mascot{height:76px;max-width:100%;margin:14px 0 0 auto}
  .poem-filter-bar{align-items:flex-start;flex-direction:column}
  .prose-filter-bar{align-items:stretch;flex-direction:column}
  .prose-search-label{margin:0}
  .prose-search{width:100%}
  .preview-overlay{padding:10px}
  .preview-body{font-size:16px}
  .cycle-card{grid-template-columns:72px minmax(0,1fr);gap:12px}
  .cycle-card-cover{width:72px;height:72px}
  .cycle-selection-heading{flex-direction:column;gap:3px}
}
@media(max-width:420px){
  .nav-link{gap:7px;padding:8px;font-size:12px}
  .nav-icon{display:none}
  .stats{grid-template-columns:1fr}
  .stat-card{display:flex;align-items:center;justify-content:space-between}
  .stat-number{margin:0}
  .stat-foot{display:none}
  .quick-actions{display:grid;grid-template-columns:1fr}
  .btn-secondary{text-align:left}
}
</style>
</head>
<body>
<div class="login" id="login">
  <div class="login-box">
    <div class="login-mark" aria-hidden="true">Р</div>
    <div class="logo">Посмертие Ринны</div>
    <div class="muted">Личный кабинет литературного архива</div>
    <label for="user">Логин</label>
    <input id="user" autocomplete="username" placeholder="Введите логин">
    <label for="pass">Пароль</label>
    <input id="pass" type="password" autocomplete="current-password" placeholder="Введите пароль" onkeydown="if(event.key==='Enter')login()">
    <button class="btn" type="button" onclick="login()">Войти в архив</button>
    <div class="error" id="error" role="alert">Неверный логин или пароль</div>
  </div>
</div>
<div class="app" id="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">Р</div>
      <div><div class="brand-name">Посмертие Ринны</div><div class="brand-caption">Литературный архив</div></div>
    </div>
    <nav class="nav" aria-label="Основная навигация">
      <button class="nav-link active" type="button" data-view="dashboard" onclick="show('dashboard',this)"><span class="nav-icon" aria-hidden="true">⌂</span>Главная</button>
      <button class="nav-link" type="button" data-view="poems" onclick="show('poems',this)"><span class="nav-icon" aria-hidden="true">✎</span>Стихи</button>
      <button class="nav-link" type="button" data-view="cycles" onclick="show('cycles',this)"><span class="nav-icon" aria-hidden="true">◌</span>Циклы</button>
      <button class="nav-link" type="button" data-view="prose" onclick="show('prose',this)"><span class="nav-icon" aria-hidden="true">▤</span>Проза</button>
      <button class="nav-link" type="button" data-view="settings" onclick="show('settings',this)"><span class="nav-icon" aria-hidden="true">⚙</span>Настройки</button>
    </nav>
    <div class="sidebar-bottom">
      <div class="sidebar-note">Тихое место для слов, которые остаются.</div>
      <button class="nav-link logout" type="button" onclick="logout()"><span class="nav-icon" aria-hidden="true">↪</span>Выйти</button>
    </div>
  </aside>
  <main class="content">
    <div class="topbar">
      <div class="crumb">Архив <span aria-hidden="true">/</span> <span id="view-title">Главная</span></div>
      <div class="topbar-user"><span class="avatar" aria-hidden="true">Р</span><span>Администратор</span></div>
    </div>
    <section class="section active" id="dashboard">
      <div class="hero">
        <div class="hero-content">
          <div class="eyebrow">Личный архив</div>
          <h1>Добро пожаловать</h1>
          <p>Здесь собраны тексты Посмертия Ринны. Продолжайте работу с архивом или начните новую запись.</p>
          <div class="quick-actions">
            <button class="btn-secondary" type="button" onclick="startPoem()"><span class="plus">＋</span>Новый стих</button>
          <button class="btn-secondary" type="button" onclick="startCycle()"><span class="plus">＋</span>Новый цикл</button>
            <button class="btn-secondary" type="button" onclick="startProse()"><span class="plus">＋</span>Новая проза</button>
          </div>
        </div>
        <img class="hero-mascot" src="/mascot.png" alt="" aria-hidden="true" width="128" height="128">
      </div>
      <div class="stats">
        <div class="stat-card"><div><div class="stat-top">Стихи <span class="stat-symbol">✎</span></div><div class="stat-number" id="poem-count">—</div><div class="stat-foot">в архиве</div></div></div>
        <div class="stat-card"><div><div class="stat-top">Циклы <span class="stat-symbol">◌</span></div><div class="stat-number" id="cycle-count">0</div><div class="stat-foot">раздел в разработке</div></div></div>
        <div class="stat-card"><div><div class="stat-top">Проза <span class="stat-symbol">▤</span></div><div class="stat-number" id="prose-count">—</div><div class="stat-foot">в архиве</div></div></div>
      </div>
      <div class="dashboard-grid">
        <div class="panel">
          <div class="panel-heading"><h2>Последние изменения</h2><span class="panel-kicker">Недавние записи</span></div>
          <div class="recent-list" id="recent-list"><div class="empty-note">Загружаем архив…</div></div>
        </div>
        <div>
          <div class="panel">
            <div class="panel-heading"><h2>Черновики</h2><span class="panel-kicker">Личные заметки</span></div>
            <div class="draft-empty"><div class="draft-mark" aria-hidden="true">⌁</div><strong>Пока нет черновиков</strong><p>Сохранённые стихотворения сразу попадают в архив.</p></div>
          </div>
          <div class="storage-card" aria-live="polite">
            <span class="status-dot" id="storage-dot"></span>
            <div><div class="storage-title" id="storage-title">Проверяем хранилище</div><div class="storage-copy" id="storage-copy">Связь с архивом GitHub</div></div>
          </div>
        </div>
      </div>
    </section>
    <section class="section" id="poems">
      <div class="section-top">
        <div class="page-heading"><div class="eyebrow">Коллекция</div><h1>Стихи</h1><div class="subtitle">Стихотворения в литературном архиве</div></div>
        <button class="btn add" type="button" onclick="openPoemForm()">＋ Новое стихотворение</button>
      </div>
      <div class="panel poem-panel">
        <form id="poem-form" onsubmit="savePoem(event)" style="display:none">
          <input id="poem-id" type="hidden">
          <div class="panel-heading"><h2 id="poem-form-heading">Новое стихотворение</h2></div>
          <div class="editor-fields">
            <div class="editor-field editor-field-wide">
              <label for="poem-title">Название</label>
              <input id="poem-title" name="title" required maxlength="300" placeholder="Название стихотворения">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="poem-text">Текст</label>
              <textarea id="poem-text" name="text" rows="10" required placeholder="Начните писать…"></textarea>
            </div>
            <div class="editor-field">
              <label for="poem-date">Дата</label>
              <input id="poem-date" name="date" type="date">
            </div>
            <div class="editor-field">
              <label for="poem-status">Статус</label>
              <select id="poem-status" name="status">
                <option value="published">Опубликовано</option>
                <option value="draft">Черновик</option>
              </select>
            </div>
            <div class="editor-field editor-field-wide"><div id="poem-image-editor"></div></div>
          </div>
          <div class="poem-cycle-editor">
            <div class="poem-cycle-editor-title">Циклы</div>
            <div id="poem-editor-cycles" class="poem-editor-cycle-note">Загрузка циклов…</div>
            <div class="poem-editor-cycle-note">Принадлежность к циклам меняется в разделе «Циклы».</div>
          </div>
          <div class="editor-actions">
            <button class="btn" type="submit">Сохранить</button>
            <button class="btn-secondary" type="submit" data-save-status="draft">Сохранить как черновик</button>
            <button class="btn-secondary" type="button" onclick="previewPoemForm()">Предпросмотр</button>
            <button class="btn-secondary" type="button" onclick="closePoemForm()">Закрыть</button>
            <button class="btn-danger" id="poem-delete" type="button" onclick="deleteEditingPoem()" hidden>Удалить</button>
          </div>
        </form>
        <div class="error" id="poem-error" role="alert"></div>
        <div class="poem-filter-bar">
          <div class="poem-cycle-filter" role="group" aria-label="Фильтр по циклам">
            <button class="active" type="button" data-poem-filter="all" onclick="setPoemCycleFilter('all')">Все</button>
            <button type="button" data-poem-filter="outside" onclick="setPoemCycleFilter('outside')">Вне циклов</button>
            <button type="button" data-poem-filter="inside" onclick="setPoemCycleFilter('inside')">В циклах</button>
          </div>
          <span class="poem-filter-count" id="poem-filter-count"></span>
        </div>
        <div class="error" id="poem-cycles-error" role="alert"></div>
        <div class="poem-list" id="poem-list"></div>
      </div>
      <div class="preview-overlay" id="poem-preview" hidden onclick="if(event.target===this)closePoemPreview()">
      <article class="preview-dialog" role="dialog" aria-modal="true" aria-labelledby="preview-title">
        <div class="preview-toolbar"><span>PREVIEW / POETRY</span><button class="btn-secondary" type="button" onclick="closePoemPreview()">Закрыть <span aria-hidden="true">×</span></button></div>
        <div class="preview-poem">
          <div class="preview-index">ПОСМЕРТИЕ РИННЫ · АРХИВ</div>
          <h2 id="preview-title"></h2>
          <div class="preview-date" id="preview-date"></div>
          <figure class="preview-figure" id="preview-figure" hidden><div class="illustration-frame" id="preview-image-frame"><img id="preview-image" alt=""></div><figcaption id="preview-caption"><span class="archive-meta-caption" hidden></span><span class="image-caption-text"></span></figcaption></figure>
          <div class="preview-body" id="preview-body"></div>
          <div class="preview-status" id="preview-status"></div>
        </div>
      </article>
    </div>
    </section>
    <section class="section" id="cycles">
      <div class="section-top">
        <div class="page-heading"><div class="eyebrow">Структура архива</div><h1>Циклы</h1><div class="subtitle">Тематические собрания стихотворений</div></div>
        <button class="btn add" type="button" onclick="openCycleForm()">＋ Новый цикл</button>
      </div>
      <div class="panel cycle-panel">
        <form id="cycle-form" onsubmit="saveCycle(event)" style="display:none">
          <input id="cycle-id" type="hidden">
          <div class="panel-heading"><h2 id="cycle-form-heading">Новый цикл</h2></div>
          <div class="editor-fields">
            <div class="editor-field editor-field-wide">
              <label for="cycle-title">Название</label>
              <input id="cycle-title" name="title" required maxlength="300" placeholder="Название цикла">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="cycle-description">Описание</label>
              <textarea id="cycle-description" name="description" rows="4" maxlength="10000" placeholder="Коротко о цикле"></textarea>
            </div>
            <div class="editor-field">
              <label for="cycle-status">Статус</label>
              <select id="cycle-status" name="status">
                <option value="published">Опубликован</option>
                <option value="draft">Черновик</option>
              </select>
            </div>
            <div class="editor-field editor-field-wide"><div id="cycle-image-editor"></div></div>
            <div class="editor-field editor-field-wide">
              <label for="cycle-poem-picker">Добавить существующее стихотворение</label>
              <div class="cycle-picker">
                <select id="cycle-poem-picker" aria-label="Выберите стихотворение"></select>
                <button class="btn-secondary" id="cycle-add-poem" type="button" onclick="addPoemToCycle()">Добавить стих</button>
              </div>
              <div class="cycle-selection-heading">Стихи в цикле <span>Порядок можно менять кнопками ↑ и ↓</span></div>
              <div class="cycle-selected-list" id="cycle-selected-poems"></div>
            </div>
          </div>
          <div class="editor-actions">
            <button class="btn" type="submit">Сохранить цикл</button>
            <button class="btn-secondary" type="button" onclick="previewCycleForm()">Предпросмотр</button>
            <button class="btn-secondary" type="button" onclick="closeCycleForm()">Закрыть</button>
            <button class="btn-danger" id="cycle-delete" type="button" onclick="deleteEditingCycle()" hidden>Удалить цикл</button>
          </div>
        </form>
        <div class="error" id="cycle-error" role="alert"></div>
        <div class="cycle-list" id="cycle-list"></div>
      </div>
      <div class="preview-overlay" id="cycle-preview" hidden onclick="if(event.target===this)closeCyclePreview()">
        <article class="preview-dialog cycle-preview-dialog" role="dialog" aria-modal="true" aria-labelledby="cycle-preview-title">
          <div class="preview-toolbar"><span>PREVIEW / CYCLE</span><button class="btn-secondary" type="button" onclick="closeCyclePreview()">Закрыть <span aria-hidden="true">×</span></button></div>
          <div class="cycle-preview-content">
            <div class="preview-index">ПОСМЕРТИЕ РИННЫ · ЦИКЛ</div>
            <h2 id="cycle-preview-title"></h2>
            <p class="cycle-preview-description" id="cycle-preview-description"></p>
            <figure class="cycle-preview-figure" id="cycle-preview-figure" hidden><div class="illustration-frame" id="cycle-preview-image-frame"><img class="cycle-preview-cover" id="cycle-preview-cover" alt="" hidden></div><figcaption id="cycle-preview-caption"><span class="archive-meta-caption" hidden></span><span class="image-caption-text"></span></figcaption></figure>
            <div class="cycle-preview-poems" id="cycle-preview-poems"></div>
            <div class="preview-status" id="cycle-preview-status"></div>
          </div>
        </article>
      </div>
    </section>
    
    <section class="section" id="prose">
      <div class="section-top">
        <div class="page-heading"><div class="eyebrow">Другие тексты</div><h1>Проза</h1><div class="subtitle">Рассказы и произведения в прозе</div></div>
        <button class="btn add" type="button" onclick="openProseForm()">＋ Новая проза</button>
      </div>
      <div class="panel poem-panel prose-panel">
        <form id="prose-form" onsubmit="saveProse(event)" style="display:none">
          <input id="prose-id" type="hidden">
          <div class="panel-heading"><h2 id="prose-form-heading">Новая проза</h2></div>
          <div class="editor-fields">
            <div class="editor-field editor-field-wide">
              <label for="prose-title">Название</label>
              <input id="prose-title" name="title" required maxlength="300" placeholder="Название произведения">
            </div>
            <div class="editor-field">
              <label for="prose-type">Тип</label>
              <select id="prose-type" name="type" required>
                <option value="story">Рассказ</option>
                <option value="novel">Роман</option>
                <option value="chapter">Глава</option>
              </select>
            </div>
            <div class="editor-field">
              <label for="prose-date">Дата</label>
              <input id="prose-date" name="date" type="date">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="prose-description">Краткое описание</label>
              <textarea id="prose-description" name="description" rows="3" maxlength="10000" placeholder="О чём это произведение"></textarea>
            </div>
            <div class="editor-field editor-field-wide">
              <label for="prose-text">Полный текст</label>
              <textarea id="prose-text" name="text" rows="12" placeholder="Начните писать…"></textarea>
            </div>
            <div class="editor-field">
              <label for="prose-status">Статус</label>
              <select id="prose-status" name="status">
                <option value="published">Опубликовано</option>
                <option value="draft">Черновик</option>
              </select>
            </div>
            <div class="editor-field editor-field-wide"><div id="prose-image-editor"></div></div>
          </div>
          <div class="editor-actions">
            <button class="btn" type="submit">Сохранить</button>
            <button class="btn-secondary" type="submit" data-save-status="draft">Сохранить как черновик</button>
            <button class="btn-secondary" type="button" onclick="previewProseForm()">Предпросмотр</button>
            <button class="btn-secondary" type="button" onclick="closeProseForm()">Отмена</button>
            <button class="btn-danger" id="prose-delete" type="button" onclick="deleteEditingProse()" hidden>Удалить</button>
          </div>
        </form>
        <div class="error" id="prose-error" role="alert"></div>
        <div class="prose-filter-bar">
          <div class="poem-cycle-filter" role="group" aria-label="Фильтр прозы по статусу">
            <button class="active" type="button" data-prose-filter="all" onclick="setProseFilter('all')">Все</button>
            <button type="button" data-prose-filter="published" onclick="setProseFilter('published')">Опубликованные</button>
            <button type="button" data-prose-filter="draft" onclick="setProseFilter('draft')">Черновики</button>
          </div>
          <label class="prose-search-label" for="prose-search">Поиск по названию</label>
          <input class="prose-search" id="prose-search" type="search" placeholder="Название произведения" oninput="setProseSearch(this.value)">
          <span class="poem-filter-count" id="prose-filter-count"></span>
        </div>
        <div class="prose-list" id="prose-list"></div>
      </div>
      <div class="preview-overlay" id="prose-preview" hidden onclick="if(event.target===this)closeProsePreview()">
        <article class="preview-dialog" role="dialog" aria-modal="true" aria-labelledby="prose-preview-title">
          <div class="preview-toolbar"><span>PREVIEW / PROSE</span><button class="btn-secondary" type="button" onclick="closeProsePreview()">Закрыть <span aria-hidden="true">×</span></button></div>
          <div class="preview-poem prose-preview-content">
            <div class="preview-index">ПОСМЕРТИЕ РИННЫ · АРХИВ</div>
            <h2 id="prose-preview-title"></h2>
            <div class="preview-date" id="prose-preview-meta"></div>
            <p class="prose-preview-description" id="prose-preview-description" hidden></p>
            <figure class="preview-figure" id="prose-preview-figure" hidden><div class="illustration-frame" id="prose-preview-image-frame"><img id="prose-preview-image" alt=""></div><figcaption id="prose-preview-caption"><span class="archive-meta-caption" hidden></span><span class="image-caption-text"></span></figcaption></figure>
            <div class="preview-body" id="prose-preview-body"></div>
            <div class="preview-status" id="prose-preview-status"></div>
          </div>
        </article>
      </div>
    </section>
    <section class="section" id="settings">
      <div class="page-heading"><div class="eyebrow">Архив</div><h1>Настройки</h1><div class="subtitle">Состояние и сведения о панели</div></div>
      <div class="panel placeholder-panel"><div class="placeholder-glyph" aria-hidden="true">⚙</div><h2>Настройки архива</h2><div class="settings-row"><span>Хранилище стихов</span><span class="settings-value">GitHub Contents API</span></div><div class="settings-row"><span>Ветка данных</span><span class="settings-value">poems-data</span></div><div class="settings-row"><span>Сессия администратора</span><span class="settings-value">Защищённая, до 8 часов</span></div></div>
    </section>
    <div class="preview-overlay" id="image-effect-overlay" hidden onclick="if(event.target===this)closeImageEffect(false)">
      <section class="image-effect-dialog" role="dialog" aria-modal="true" aria-labelledby="image-effect-title">
        <div class="preview-toolbar"><span>EDITOR / IMAGE EFFECT</span><button class="btn-secondary" type="button" onclick="closeImageEffect(false)">Закрыть <span aria-hidden="true">×</span></button></div>
        <div class="image-effect-content">
          <div class="panel-heading"><div><span class="panel-kicker">VISUAL SETTINGS</span><h2 id="image-effect-title">Эффект изображения</h2></div></div>
          <div class="image-effect-controls">
            <div class="editor-field"><label for="image-effect-select">Эффект</label><select id="image-effect-select" onchange="updateImageEffectDraft()"><option value="none">Нет</option><option value="fade">Плавное появление</option><option value="darken">Затемнение</option><option value="scale">Увеличение</option><option value="glow">Свечение</option><option value="archive">Archive</option></select></div>
            <div class="editor-field"><label for="image-position-select">Позиция</label><select id="image-position-select" onchange="updateImageEffectDraft()"><option value="center">Центр</option><option value="top">Сверху</option><option value="bottom">Снизу</option><option value="left">Слева</option><option value="right">Справа</option></select></div>
            <div class="editor-field"><label for="image-scale-range">Масштаб <output id="image-scale-value">100%</output></label><input id="image-scale-range" type="range" min="80" max="150" step="1" value="100" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-intensity-range">Интенсивность <output id="image-intensity-value">50%</output></label><input id="image-intensity-range" type="range" min="0" max="100" step="1" value="50" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-overlay-range">Затемнение / Overlay <output id="image-overlay-value">0%</output></label><input id="image-overlay-range" type="range" min="0" max="100" step="1" value="0" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-hover-select">Эффект при наведении</label><select id="image-hover-select" onchange="updateImageEffectDraft(true)"><option value="none">Нет</option><option value="scale">Увеличение</option><option value="glow">Свечение</option></select></div>
            <div class="editor-field"><label><input id="image-watermark-toggle" type="checkbox" onchange="updateImageEffectDraft()"> Показывать watermark</label></div>
            <div class="editor-field"><label for="image-watermark-position">Позиция watermark</label><select id="image-watermark-position" onchange="updateImageEffectDraft()"><option value="top-left">Сверху слева</option><option value="top-right">Сверху справа</option><option value="center">По центру</option><option value="bottom-left">Снизу слева</option><option value="bottom-right">Снизу справа</option></select></div>
            <div class="editor-field editor-field-wide"><label for="image-watermark-opacity">Прозрачность watermark <output id="image-watermark-opacity-value">42%</output></label><input id="image-watermark-opacity" type="range" min="0" max="100" step="1" value="42" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field editor-field-wide archive-settings-heading"><span class="panel-kicker">АРХИВНАЯ РАЗМЕТКА</span></div>
            <div class="editor-field editor-field-wide"><label for="visual-record-label">Визуальная метка</label><input id="visual-record-label" type="text" maxlength="160" placeholder="POEM // VISUAL RECORD" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field editor-field-wide"><label for="image-meta-prefix">Тип иллюстрации</label><input id="image-meta-prefix" type="text" maxlength="80" placeholder="ИЛЛЮСТРАЦИЯ" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-meta-section">Раздел</label><input id="image-meta-section" type="text" maxlength="120" placeholder="СЕВЕРНЫЙ СОЮЗ" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-meta-title">Название</label><input id="image-meta-title" type="text" maxlength="160" placeholder="ГЛАВА 01" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label for="image-corner-label">Угловая метка</label><input id="image-corner-label" type="text" maxlength="100" placeholder="NORD // 01" oninput="updateImageEffectDraft()"></div>
            <div class="editor-field"><label><input id="image-archive-markup" type="checkbox" onchange="updateImageEffectDraft()"> Показывать архивную разметку</label></div>
            <div class="editor-field editor-field-wide archive-live-preview-label"><span class="panel-kicker">LIVE PREVIEW / ARCHIVE</span></div>
            <div class="image-effect-preview-frame archive-preview-frame" id="image-effect-preview-frame" data-empty="true">
              <img id="image-effect-preview-image" alt="">
              <div class="image-effect-preview-overlay" id="image-effect-preview-overlay"></div>
              <span class="image-effect-watermark" id="image-effect-watermark" data-position="bottom-right">© Ринна</span>
              <div class="image-effect-preview-empty" id="image-effect-preview-empty">Выберите изображение, чтобы увидеть preview</div>
            </div>
            <div class="archive-meta-caption image-effect-preview-meta" id="image-effect-preview-meta" hidden></div>
            <div class="editor-field editor-field-wide"><label for="image-effect-caption">Подпись к изображению</label><input id="image-effect-caption" type="text" maxlength="500" placeholder="Подпись"></div>
          </div>
          <button class="btn-secondary image-hover-toggle" id="image-hover-toggle" type="button" onclick="toggleImageHoverPreview()">Показать hover</button>
          <div class="editor-actions"><button class="btn" type="button" onclick="closeImageEffect(true)">Сохранить</button><button class="btn-secondary" type="button" onclick="closeImageEffect(false)">Отмена</button></div>
        </div>
      </section>
    </div>
  </main>
</div>
<script>
let poems = [];
let poemsLoaded = false;
let poemCycleFilter = 'all';
const viewNames = {dashboard:'Главная',poems:'Стихи',cycles:'Циклы',prose:'Проза',settings:'Настройки'};
let cycles = [];
let cyclesLoaded = false;
let cyclesLoadError = '';
let cyclesLoadPromise = null;
let editingCycleId = '';
let editingCyclePoemIds = [];
let proseEntries = [];
let proseLoaded = false;
let proseLoadPromise = null;
let proseStatusFilter = 'all';
let proseSearchTerm = '';
let editingProseId = '';
const imageEditorConfigs = {
  poems:{category:'poems',container:'poem-image-editor',imageInput:'poem-image',captionInput:'poem-caption'},
  prose:{category:'prose',container:'prose-image-editor',imageInput:'prose-image',captionInput:'prose-image-caption'},
  cycles:{category:'cycles',container:'cycle-image-editor',imageInput:'cycle-cover',captionInput:'cycle-image-caption'}
};
const clientImageBaseDefaults = {imageEffect:'none',imagePosition:'center',imageScale:100,imageIntensity:50,imageOverlay:0,imageHover:'none',imageWatermark:true,imageWatermarkOpacity:42,imageWatermarkPosition:'bottom-right',imageArchiveMarkup:true,imageMetaPrefix:'ИЛЛЮСТРАЦИЯ',imageMetaSection:'',imageMetaTitle:'',imageCornerLabel:''};
function getClientImageDefaults(key,record=null,isNew=false){
  const contentKind = key === 'poems' ? 'poem' : key === 'cycles' ? 'cycle' : 'prose';
  const defaults = {...clientImageBaseDefaults,visualRecordLabel:contentKind === 'poem' ? 'POEM // VISUAL RECORD' : contentKind === 'cycle' ? 'CYCLE // VISUAL RECORD' : 'CHAPTER // VISUAL RECORD'};
  if(isNew && !record && key === 'poems') defaults.imageMetaSection = 'СТИХОТВОРЕНИЕ';
  if(isNew && !record && key === 'cycles') defaults.imageMetaSection = 'ЦИКЛ';
  if(key === 'prose'){
    defaults.imageMetaSection = 'СЕВЕРНЫЙ СОЮЗ';
    defaults.imageMetaTitle = 'ГЛАВА 01';
  }
  if(record){
    for(const field of ['visualRecordLabel','imageMetaPrefix','imageMetaSection','imageMetaTitle','imageCornerLabel']) if(typeof record[field] === 'string') defaults[field] = record[field];
    if(typeof record.imageArchiveMarkup === 'boolean') defaults.imageArchiveMarkup = record.imageArchiveMarkup;
  }
  return defaults;
}
function createImageEditorState(key='poems',record=null,isNew=false){
  return {image:'',imageCaption:'',imageName:'',imageSize:0,...getClientImageDefaults(key,record,isNew),initialImage:'',pendingDeletePaths:[],newUploads:[]};
}
let imageEditorStates = {poems:createImageEditorState('poems',null,true),prose:createImageEditorState('prose',null,true),cycles:createImageEditorState('cycles',null,true)};
let activeImageEditor = '';
let imageEffectDraft = null;
let imageHoverPreview = false;

function mountImageEditor(key){
  const config = imageEditorConfigs[key];
  const container = document.getElementById(config.container);
  if(!container) return;
  container.innerHTML = \`<div class="image-editor">
    <div class="panel-heading"><h2>Иллюстрация</h2><span class="panel-kicker">IMAGE / \${config.category.toUpperCase()}</span></div>
    <div class="image-editor-layout">
      <div class="image-editor-preview" data-empty="true"><img id="image-preview-\${key}" alt="" draggable="false" hidden><span class="image-watermark-layer" data-position="bottom-right" id="image-watermark-\${key}" hidden>© Ринна</span><div class="image-editor-placeholder" id="image-placeholder-\${key}">Предпросмотр изображения</div></div>
      <div class="image-editor-controls">
        <div class="image-editor-actions"><button class="btn-secondary" type="button" onclick="document.getElementById('image-file-\${key}').click()">Выбрать файл</button><input id="image-file-\${key}" type="file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" hidden onchange="uploadEditorImage('\${key}',this)"><button class="btn-danger" type="button" onclick="removeEditorImage('\${key}')">Удалить изображение</button></div>
        <div class="image-editor-meta"><span id="image-name-\${key}">Файл не выбран</span><span id="image-size-\${key}"></span></div>
        <label for="\${config.imageInput}">URL или путь</label><input id="\${config.imageInput}" name="image" type="text" inputmode="url" maxlength="2048" placeholder="/images/\${config.category}/… или https://…" oninput="updateEditorImageUrl('\${key}',this.value)">
        <label for="\${config.captionInput}">Подпись к изображению <span class="optional">необязательно</span></label><input id="\${config.captionInput}" name="imageCaption" type="text" maxlength="500" placeholder="Подпись">
        <button class="btn-secondary image-effect-button" type="button" onclick="openImageEffect('\${key}')">✦ Настроить эффект</button>
        <div class="image-editor-error" id="image-error-\${key}" role="alert"></div>
      </div>
    </div>
  </div>\`;
  renderImageEditorPreview(key);
}
function mountAllImageEditors(){
  Object.keys(imageEditorConfigs).forEach(mountImageEditor);
}
function isManagedEditorImage(image,category){
  if(typeof image !== 'string' || !image.startsWith('/images/' + category + '/')) return false;
  const fileName = image.slice(image.lastIndexOf('/') + 1);
  const dot = fileName.lastIndexOf('.');
  const hash = fileName.slice(0,dot);
  const extension = fileName.slice(dot + 1).toLowerCase();
  return /^[a-f0-9]{64}$/i.test(hash) && ['jpg','jpeg','png','webp'].includes(extension);
}
function scheduleImageDeletion(key,image){
  const state = imageEditorStates[key];
  if(isManagedEditorImage(image,imageEditorConfigs[key].category) && !state.pendingDeletePaths.includes(image)) state.pendingDeletePaths.push(image);
}
function setEditorImage(key,value,fileMetadata={}){
  const state = imageEditorStates[key];
  if(state.image && state.image !== value) scheduleImageDeletion(key,state.image);
  state.pendingDeletePaths = state.pendingDeletePaths.filter(image=>image !== value);
  const sameImage = state.image === value;
  state.image = value;
  if(Object.prototype.hasOwnProperty.call(fileMetadata,'imageName')) state.imageName = fileMetadata.imageName;
  else if(!sameImage) state.imageName = value ? value.split('/').pop() : '';
  if(Object.prototype.hasOwnProperty.call(fileMetadata,'imageSize')) state.imageSize = fileMetadata.imageSize;
  else if(!sameImage) state.imageSize = 0;
  const input = document.getElementById(imageEditorConfigs[key].imageInput);
  if(input) input.value = value;
  renderImageEditorPreview(key);
  if(activeImageEditor === key) renderImageEffectPreview();
}
function updateImageEditorUrl(key,value){
  setEditorImage(key,value);
}
function formatImageSize(size){
  if(!size) return '';
  return size >= 1024 * 1024 ? (size / (1024 * 1024)).toFixed(2) + ' MB' : Math.max(1,Math.round(size / 1024)) + ' KB';
}
function ensureArchiveOverlay(frame){
  let overlay = frame.querySelector('.archive-overlay');
  if(overlay) return overlay;
  overlay = document.createElement('div');
  overlay.className = 'archive-overlay';
  overlay.hidden = true;
  const grid = document.createElement('span'); grid.className = 'archive-grid';
  const outline = document.createElement('span'); outline.className = 'archive-outline';
  const label = document.createElement('span'); label.className = 'archive-visual-label';
  const corner = document.createElement('span'); corner.className = 'archive-corner-label';
  overlay.append(grid,outline,label,corner);
  frame.append(overlay);
  return overlay;
}
function resetImageFrameGeometry(frame){
  if(!frame) return;
  frame.style.aspectRatio = '';
  frame.dataset.empty = 'true';
  for(const side of ['top','right','bottom','left']) frame.style.setProperty('--image-inset-' + side,'0%');
}
function syncImageFrameGeometry(image,record,scaleOverride){
  const frame = image && image.parentElement;
  if(!frame || !image.naturalWidth || !image.naturalHeight) return;
  frame.style.aspectRatio = image.naturalWidth + ' / ' + image.naturalHeight;
  frame.dataset.empty = 'false';
  const effect = ['none','fade','darken','scale','zoom','glow','archive'].includes(record.imageEffect) ? (record.imageEffect === 'zoom' ? 'scale' : record.imageEffect) : 'none';
  const position = ['center','top','bottom','left','right'].includes(record.imagePosition) ? record.imagePosition : 'center';
  const intensity = (Number.isFinite(Number(record.imageIntensity)) ? Number(record.imageIntensity) : 50) / 100;
  const baseScale = Number.isFinite(Number(record.imageScale)) ? Number(record.imageScale) : 100;
  const scale = Number.isFinite(scaleOverride) ? scaleOverride : baseScale / 100 * (effect === 'scale' ? 1 + intensity * .25 : 1);
  const inset = Math.round(Math.max(0,(1 - Math.min(1,scale)) * 100) * 10000) / 10000;
  let top = inset / 2, right = inset / 2, bottom = inset / 2, left = inset / 2;
  if(position === 'top'){top=0;bottom=inset;}
  else if(position === 'bottom'){top=inset;bottom=0;}
  else if(position === 'left'){left=0;right=inset;}
  else if(position === 'right'){left=inset;right=0;}
  frame.style.setProperty('--image-inset-top',top + '%');
  frame.style.setProperty('--image-inset-right',right + '%');
  frame.style.setProperty('--image-inset-bottom',bottom + '%');
  frame.style.setProperty('--image-inset-left',left + '%');
  const origins = {center:'50% 50%',top:'50% 0%',bottom:'50% 100%',left:'0% 50%',right:'100% 50%'};
  image.style.transformOrigin = origins[position];
}
function renderImageDarkening(frame,record){
  if(!frame) return;
  let layer = frame.querySelector(':scope > .image-effect-preview-overlay, :scope > .image-darkening-layer');
  if(!layer){
    layer = document.createElement('div');
    layer.className = 'image-darkening-layer';
    frame.append(layer);
  }
  const overlay = Math.max(0,Math.min(100,Number(record && record.imageOverlay) || 0)) / 100 * .65;
  const archiveBase = record && record.imageEffect === 'archive' ? .12 : 0;
  const opacity = 1 - (1 - archiveBase) * (1 - overlay);
  layer.style.background = 'rgba(0,0,0,' + opacity + ')';
  layer.hidden = opacity <= 0;
}
function renderImageWatermark(frame,record){
  if(!frame) return;
  let watermark = frame.querySelector(':scope > .image-watermark-layer');
  if(!watermark){
    watermark = document.createElement('span');
    watermark.className = 'image-watermark-layer';
    watermark.textContent = '© Ринна';
    frame.append(watermark);
  }
  const enabled = !record || record.imageWatermark !== false;
  const opacity = Number.isInteger(Number(record && record.imageWatermarkOpacity)) && Number(record.imageWatermarkOpacity) >= 0 && Number(record.imageWatermarkOpacity) <= 100 ? Number(record.imageWatermarkOpacity) : 42;
  const position = ['top-left','top-right','center','bottom-left','bottom-right'].includes(record && record.imageWatermarkPosition) ? record.imageWatermarkPosition : 'bottom-right';
  watermark.hidden = !enabled || !frame.querySelector('img:not([hidden])');
  watermark.dataset.position = position;
  watermark.style.opacity = String(opacity / 100);
}
function renderArchiveMarkup(frame,record,contentKind='poem'){
  if(!frame) return;
  const effect = record && record.imageEffect === 'archive';
  frame.classList.toggle('archive-frame',effect);
  const overlay = ensureArchiveOverlay(frame);
  const visible = effect && record.imageArchiveMarkup !== false;
  overlay.hidden = !visible;
  const metaTarget = frame.id === 'image-effect-preview-frame'
    ? document.getElementById('image-effect-preview-meta')
    : frame.parentElement && frame.parentElement.querySelector('figcaption .archive-meta-caption');
  if(!visible){
    if(metaTarget){metaTarget.textContent='';metaTarget.hidden=true;}
    return;
  }
  const fallbackLabel = contentKind === 'poem' ? 'POEM // VISUAL RECORD' : contentKind === 'cycle' ? 'CYCLE // VISUAL RECORD' : 'CHAPTER // VISUAL RECORD';
  const labelText = typeof record.visualRecordLabel === 'string' ? record.visualRecordLabel.trim() : fallbackLabel;
  const cornerText = typeof record.imageCornerLabel === 'string' ? record.imageCornerLabel.trim() : '';
  const metaSection = record.imageMetaSection === undefined && contentKind === 'prose' ? 'СЕВЕРНЫЙ СОЮЗ' : record.imageMetaSection;
  const metaTitle = record.imageMetaTitle === undefined && contentKind === 'prose' ? 'ГЛАВА 01' : record.imageMetaTitle;
  const parts = [record.imageMetaPrefix === undefined ? 'ИЛЛЮСТРАЦИЯ' : record.imageMetaPrefix,metaSection,metaTitle].map(value=>typeof value === 'string' ? value.trim() : '').filter(Boolean);
  const metaText = parts.length ? '// ' + parts.join(' // ') + ' //' : '';
  overlay.querySelector('.archive-visual-label').textContent = labelText;
  overlay.querySelector('.archive-visual-label').hidden = !labelText;
  overlay.querySelector('.archive-corner-label').textContent = cornerText;
  overlay.querySelector('.archive-corner-label').hidden = !cornerText;
  if(metaTarget){metaTarget.textContent=metaText;metaTarget.hidden=!metaText;}
}
function renderImageEditorPreview(key){
  const state = imageEditorStates[key];
  const config = imageEditorConfigs[key];
  const image = document.getElementById('image-preview-' + key);
  const placeholder = document.getElementById('image-placeholder-' + key);
  if(!image || !placeholder) return;
  const watermark = document.getElementById('image-watermark-' + key);
  const frame = image.parentElement;
  const source = safeImageSource(state.image);
  if(source){
    image.onerror = ()=>{image.hidden = true;placeholder.hidden = false;placeholder.textContent = 'Не удалось загрузить preview';resetImageFrameGeometry(frame);renderImageWatermark(frame,state);renderArchiveMarkup(frame,{imageEffect:'none'});};
    image.onload = ()=>{image.hidden = false;placeholder.hidden = true;applySavedImageEffects(image,state,key === 'poems' ? 'poem' : key === 'cycles' ? 'cycle' : 'prose');};
    const resolvedSource = new URL(source,window.location.origin).href;
    if(image.src !== resolvedSource){resetImageFrameGeometry(frame);image.src = source;}
    image.hidden = false;
    placeholder.hidden = true;
  }else{
    resetImageFrameGeometry(frame);
    image.removeAttribute('src');
    image.hidden = true;
    placeholder.hidden = false;
    placeholder.textContent = 'Предпросмотр изображения';
  }
  renderImageWatermark(frame,state);
  if(source) applySavedImageEffects(image,state,key === 'poems' ? 'poem' : key === 'cycles' ? 'cycle' : 'prose');
  else{
    renderImageDarkening(frame,{imageEffect:'none',imageOverlay:0});
    renderArchiveMarkup(frame,{imageEffect:'none'},key === 'poems' ? 'poem' : key === 'cycles' ? 'cycle' : 'prose');
  }
  const name = document.getElementById('image-name-' + key);
  const size = document.getElementById('image-size-' + key);
  if(name) name.textContent = state.imageName || (state.image ? state.image.split('/').pop() : 'Файл не выбран');
  if(size) size.textContent = state.imageSize ? formatImageSize(state.imageSize) : '';
  const error = document.getElementById('image-error-' + key);
  if(error && !error.dataset.keepError){error.textContent='';error.classList.remove('visible');}
  if(activeImageEditor === key) renderImageEffectPreview();
}
function initializeImageEditor(key,record){
  const config = imageEditorConfigs[key];
  const defaults = getClientImageDefaults(key,record,!record);
  const state = createImageEditorState(key,record,!record);
  state.image = (record && (record.image || (key === 'cycles' && record.cover))) || '';
  state.imageCaption = record ? (typeof record.imageCaption === 'string' ? record.imageCaption : (key === 'poems' && typeof record.caption === 'string' ? record.caption : '')) : '';
  state.imageName = record && record.imageName || (state.image ? state.image.split('/').pop() : '');
  state.imageSize = record && Number(record.imageSize) || 0;
  for(const setting of Object.keys(defaults)){
    if(!record || record[setting] === undefined) continue;
    const value = record[setting];
    if(setting === 'imageEffect' && ['none','fade','darken','scale','zoom','glow','archive'].includes(value)) state[setting] = value === 'zoom' ? 'scale' : value;
    else if(setting === 'imagePosition' && ['center','top','bottom','left','right'].includes(value)) state[setting] = value;
    else if(setting === 'imageHover' && ['none','scale','zoom','glow'].includes(value)) state[setting] = value === 'zoom' ? 'scale' : value;
    else if(setting === 'imageWatermark' && typeof value === 'boolean') state[setting] = value;
    else if(setting === 'imageWatermarkPosition' && ['top-left','top-right','center','bottom-left','bottom-right'].includes(value)) state[setting] = value;
    else if(setting === 'imageArchiveMarkup' && typeof value === 'boolean') state[setting] = value;
    else if(['visualRecordLabel','imageMetaPrefix','imageMetaSection','imageMetaTitle','imageCornerLabel'].includes(setting) && typeof value === 'string') state[setting] = value;
    else if(['imageScale','imageIntensity','imageOverlay','imageWatermarkOpacity'].includes(setting) && Number.isInteger(Number(value))){
      const number = Number(value);
      const min = setting === 'imageScale' ? 80 : 0;
      const max = setting === 'imageScale' ? 150 : 100;
      if(number >= min && number <= max) state[setting] = number;
    }
  }
  state.initialImage = state.image;
  imageEditorStates[key] = state;
  const imageInput = document.getElementById(config.imageInput);
  const captionInput = document.getElementById(config.captionInput);
  if(imageInput) imageInput.value = state.image;
  if(captionInput) captionInput.value = state.imageCaption;
  const fileInput = document.getElementById('image-file-' + key);
  if(fileInput) fileInput.value = '';
  renderImageEditorPreview(key);
}
function getImageEditorData(key){
  const config = imageEditorConfigs[key];
  const state = imageEditorStates[key];
  const imageInput = document.getElementById(config.imageInput);
  const captionInput = document.getElementById(config.captionInput);
  state.image = imageInput ? imageInput.value.trim() : state.image;
  state.imageCaption = captionInput ? captionInput.value.trim() : state.imageCaption;
  return {image:state.image,imageCaption:state.imageCaption,imageName:state.imageName,imageSize:state.imageSize,imageEffect:state.imageEffect,imagePosition:state.imagePosition,imageScale:state.imageScale,imageIntensity:state.imageIntensity,imageOverlay:state.imageOverlay,imageHover:state.imageHover,imageWatermark:state.imageWatermark,imageWatermarkOpacity:state.imageWatermarkOpacity,imageWatermarkPosition:state.imageWatermarkPosition,imageArchiveMarkup:state.imageArchiveMarkup,visualRecordLabel:state.visualRecordLabel,imageMetaPrefix:state.imageMetaPrefix,imageMetaSection:state.imageMetaSection,imageMetaTitle:state.imageMetaTitle,imageCornerLabel:state.imageCornerLabel};
}
function showImageEditorError(key,message){
  const error = document.getElementById('image-error-' + key);
  if(!error) return;
  error.textContent = message;
  error.classList.add('visible');
}
function encodeImageBase64(bytes){
  let binary = '';
  for(let offset=0;offset<bytes.length;offset+=0x8000) binary += String.fromCharCode(...bytes.subarray(offset,offset+0x8000));
  return btoa(binary);
}
async function uploadEditorImage(key,input){
  const file = input.files && input.files[0];
  if(!file) return;
  const extension = file.name.slice(file.name.lastIndexOf('.') + 1).toLowerCase();
  const expectedMime = extension === 'jpg' || extension === 'jpeg' ? 'image/jpeg' : extension === 'png' ? 'image/png' : extension === 'webp' ? 'image/webp' : '';
  const allowed = !!expectedMime && (!file.type || file.type.toLowerCase() === expectedMime);
  if(!allowed){showImageEditorError(key,'Поддерживаются только JPG, JPEG, PNG и WebP.');input.value='';return;}
  if(file.size > 10 * 1024 * 1024){showImageEditorError(key,'Размер изображения не должен превышать 10 MiB.');input.value='';return;}
  if(!file.size){showImageEditorError(key,'Файл изображения пуст.');input.value='';return;}
  const state = imageEditorStates[key];
  const button = document.querySelector('#' + imageEditorConfigs[key].container + ' .image-editor-actions button');
  if(button) button.disabled = true;
  showImageEditorError(key,'Загружаем изображение в GitHub…');
  try{
    const contentBase64 = encodeImageBase64(new Uint8Array(await file.arrayBuffer()));
    const response = await fetch('/api/images/upload',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({category:imageEditorConfigs[key].category,fileName:file.name,contentType:expectedMime,contentBase64})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось загрузить изображение');
    if(!state.newUploads.includes(result.image) && result.image !== state.initialImage) state.newUploads.push(result.image);
    setEditorImage(key,result.image,{imageName:result.imageName || file.name,imageSize:result.imageSize || file.size});
    const error = document.getElementById('image-error-' + key);
    error.dataset.keepError = '';
    error.textContent = '';
    error.classList.remove('visible');
  }catch(error){
    showImageEditorError(key,error.message);
  }finally{
    if(button) button.disabled = false;
    input.value = '';
  }
}
function removeEditorImage(key){
  setEditorImage(key,'',{imageName:'',imageSize:0});
}
async function deleteManagedImage(category,image){
  const response = await fetch('/api/images/delete',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category,image})
  });
  const result = await response.json();
  if(!response.ok) throw new Error(result.error || 'Не удалось удалить изображение');
}
async function finalizeImageEditorSave(key){
  const state = imageEditorStates[key];
  const paths = [...new Set([...state.pendingDeletePaths,...state.newUploads])].filter(image=>image !== state.image);
  const errors = [];
  for(const image of paths){
    try{await deleteManagedImage(imageEditorConfigs[key].category,image);}catch(error){errors.push(error.message);}
  }
  state.pendingDeletePaths = [];
  state.newUploads = [];
  state.initialImage = state.image;
  return errors;
}
async function cleanupUncommittedImageUploads(key){
  const state = imageEditorStates[key];
  const paths = [...new Set(state.newUploads)].filter(image=>image !== state.initialImage);
  state.newUploads = [];
  for(const image of paths){
    if(image === state.initialImage) continue;
    try{await deleteManagedImage(imageEditorConfigs[key].category,image);}catch{}
  }
}
function openImageEffect(key){
  activeImageEditor = key;
  const state = imageEditorStates[key];
  imageEffectDraft = {imageEffect:state.imageEffect,imagePosition:state.imagePosition,imageScale:state.imageScale,imageIntensity:state.imageIntensity,imageOverlay:state.imageOverlay,imageHover:state.imageHover,imageCaption:document.getElementById(imageEditorConfigs[key].captionInput).value,imageWatermark:state.imageWatermark,imageWatermarkOpacity:state.imageWatermarkOpacity,imageWatermarkPosition:state.imageWatermarkPosition,imageArchiveMarkup:state.imageArchiveMarkup,visualRecordLabel:state.visualRecordLabel,imageMetaPrefix:state.imageMetaPrefix,imageMetaSection:state.imageMetaSection,imageMetaTitle:state.imageMetaTitle,imageCornerLabel:state.imageCornerLabel};
  imageHoverPreview = false;
  document.getElementById('image-effect-select').value = imageEffectDraft.imageEffect;
  document.getElementById('image-position-select').value = imageEffectDraft.imagePosition;
  document.getElementById('image-scale-range').value = imageEffectDraft.imageScale;
  document.getElementById('image-intensity-range').value = imageEffectDraft.imageIntensity;
  document.getElementById('image-overlay-range').value = imageEffectDraft.imageOverlay;
  document.getElementById('image-hover-select').value = imageEffectDraft.imageHover;
  document.getElementById('image-watermark-toggle').checked = imageEffectDraft.imageWatermark;
  document.getElementById('image-watermark-position').value = imageEffectDraft.imageWatermarkPosition;
  document.getElementById('image-watermark-opacity').value = imageEffectDraft.imageWatermarkOpacity;
  document.getElementById('image-archive-markup').checked = imageEffectDraft.imageArchiveMarkup;
  document.getElementById('visual-record-label').value = imageEffectDraft.visualRecordLabel;
  document.getElementById('image-meta-prefix').value = imageEffectDraft.imageMetaPrefix;
  document.getElementById('image-meta-section').value = imageEffectDraft.imageMetaSection;
  document.getElementById('image-meta-title').value = imageEffectDraft.imageMetaTitle;
  document.getElementById('image-meta-section').placeholder = key === 'poems' ? 'СТИХОТВОРЕНИЕ' : key === 'cycles' ? 'ЦИКЛ' : 'СЕВЕРНЫЙ СОЮЗ';
  document.getElementById('image-meta-title').placeholder = key === 'prose' ? 'ГЛАВА 01' : 'СПИСАНИЕ';
  document.getElementById('image-corner-label').value = imageEffectDraft.imageCornerLabel;
  document.getElementById('image-effect-caption').value = imageEffectDraft.imageCaption;
  document.getElementById('image-hover-toggle').classList.remove('active');
  document.getElementById('image-hover-toggle').textContent = 'Показать hover';
  document.getElementById('image-effect-overlay').hidden = false;
  updateImageEffectDraft();
}
function updateImageEffectDraft(previewHover=false){
  if(!imageEffectDraft) return;
  imageEffectDraft.imageEffect = document.getElementById('image-effect-select').value;
  imageEffectDraft.imagePosition = document.getElementById('image-position-select').value;
  imageEffectDraft.imageScale = Number(document.getElementById('image-scale-range').value);
  imageEffectDraft.imageIntensity = Number(document.getElementById('image-intensity-range').value);
  imageEffectDraft.imageOverlay = Number(document.getElementById('image-overlay-range').value);
  imageEffectDraft.imageHover = document.getElementById('image-hover-select').value;
  imageEffectDraft.imageCaption = document.getElementById('image-effect-caption').value;
  imageEffectDraft.imageWatermark = document.getElementById('image-watermark-toggle').checked;
  imageEffectDraft.imageWatermarkPosition = document.getElementById('image-watermark-position').value;
  imageEffectDraft.imageWatermarkOpacity = Number(document.getElementById('image-watermark-opacity').value);
  imageEffectDraft.imageArchiveMarkup = document.getElementById('image-archive-markup').checked;
  imageEffectDraft.visualRecordLabel = document.getElementById('visual-record-label').value;
  imageEffectDraft.imageMetaPrefix = document.getElementById('image-meta-prefix').value;
  imageEffectDraft.imageMetaSection = document.getElementById('image-meta-section').value;
  imageEffectDraft.imageMetaTitle = document.getElementById('image-meta-title').value;
  imageEffectDraft.imageCornerLabel = document.getElementById('image-corner-label').value;
  if(previewHover){
    imageHoverPreview = imageEffectDraft.imageHover !== 'none';
    const hoverButton = document.getElementById('image-hover-toggle');
    hoverButton.classList.toggle('active',imageHoverPreview);
    hoverButton.textContent = imageHoverPreview ? 'Скрыть hover' : 'Показать hover';
  }
  document.getElementById('image-scale-value').textContent = imageEffectDraft.imageScale + '%';
  document.getElementById('image-intensity-value').textContent = imageEffectDraft.imageIntensity + '%';
  document.getElementById('image-overlay-value').textContent = imageEffectDraft.imageOverlay + '%';
  document.getElementById('image-watermark-opacity-value').textContent = imageEffectDraft.imageWatermarkOpacity + '%';
  renderImageEffectPreview();
}
function toggleImageHoverPreview(){
  imageHoverPreview = !imageHoverPreview;
  const button = document.getElementById('image-hover-toggle');
  button.classList.toggle('active',imageHoverPreview);
  button.textContent = imageHoverPreview ? 'Скрыть hover' : 'Показать hover';
  renderImageEffectPreview();
}
function renderImageEffectPreview(){
  if(!activeImageEditor || !imageEffectDraft) return;
  const state = imageEditorStates[activeImageEditor];
  const frame = document.getElementById('image-effect-preview-frame');
  const image = document.getElementById('image-effect-preview-image');
  const watermark = document.getElementById('image-effect-watermark');
  const empty = document.getElementById('image-effect-preview-empty');
  const source = safeImageSource(state.image);
  const contentKind = activeImageEditor === 'poems' ? 'poem' : activeImageEditor === 'cycles' ? 'cycle' : 'prose';
  watermark.hidden = !imageEffectDraft.imageWatermark || !source;
  watermark.dataset.position = imageEffectDraft.imageWatermarkPosition;
  watermark.style.opacity = String(imageEffectDraft.imageWatermarkOpacity / 100);
  if(!source){
    resetImageFrameGeometry(frame);
    image.hidden=true;
    image.removeAttribute('src');
    renderImageDarkening(frame,imageEffectDraft);
    renderArchiveMarkup(frame,imageEffectDraft,contentKind);
    empty.hidden=false;
    return;
  }
  image.hidden=false;
  empty.hidden=true;
  image.onload = ()=>renderImageEffectPreview();
  image.onerror = ()=>{resetImageFrameGeometry(frame);};
  const resolvedSource = new URL(source,window.location.origin).href;
  if(image.src !== resolvedSource){resetImageFrameGeometry(frame);image.src = source;}
  const positions = {center:'50% 50%',top:'50% 0%',bottom:'50% 100%',left:'0% 50%',right:'100% 50%'};
  image.style.objectPosition = positions[imageEffectDraft.imagePosition] || '50% 50%';
  const effect = imageEffectDraft.imageEffect;
  const intensity = imageEffectDraft.imageIntensity / 100;
  let scale = imageEffectDraft.imageScale / 100 * (effect === 'scale' ? 1 + intensity * .25 : 1);
  let opacity = effect === 'fade' ? .4 + intensity * .6 : 1;
  let brightness = effect === 'darken' ? 1 - intensity * .65 : 1;
  let shadow = effect === 'glow' ? '0 0 ' + (8 + intensity * 30) + 'px rgba(238,35,73,' + (.15 + intensity * .65) + ')' : 'none';
  if(imageHoverPreview){
    if(imageEffectDraft.imageHover === 'scale') scale *= 1.12;
    if(imageEffectDraft.imageHover === 'glow') shadow = '0 0 ' + (18 + intensity * 35) + 'px rgba(238,35,73,' + (.35 + intensity * .6) + ')';
  }
  image.style.transform = 'scale(' + scale + ')';
  image.style.transformOrigin = positions[imageEffectDraft.imagePosition] || positions.center;
  image.style.opacity = String(opacity);
  image.style.filter = 'brightness(' + brightness + ')';
  image.style.boxShadow = shadow;
  syncImageFrameGeometry(image,imageEffectDraft,scale);
  renderImageDarkening(frame,imageEffectDraft);
  renderArchiveMarkup(frame,imageEffectDraft,contentKind);
  frame.dataset.hover = imageHoverPreview ? 'true' : 'false';
}
function closeImageEffect(save){
  if(!activeImageEditor){document.getElementById('image-effect-overlay').hidden=true;return;}
  if(save && imageEffectDraft){
    const state = imageEditorStates[activeImageEditor];
    Object.assign(state,imageEffectDraft);
    document.getElementById(imageEditorConfigs[activeImageEditor].captionInput).value = state.imageCaption;
    renderImageEditorPreview(activeImageEditor);
  }
  document.getElementById('image-effect-overlay').hidden = true;
  activeImageEditor = '';
  imageEffectDraft = null;
  imageHoverPreview = false;
}

async function loadPoems(){
  setStorageStatus('checking');
  try{
    const response = await fetch('/api/poems');
    if(!response.ok) throw new Error('Не удалось загрузить стихи');
    poems = await response.json();
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
  }catch(error){
    setStorageStatus('offline');
    showPoemError(error.message);
    document.getElementById('recent-list').innerHTML = '<div class="empty-note">Не удалось получить последние записи.</div>';
  }
}

function setStorageStatus(status){
  const dot = document.getElementById('storage-dot');
  const title = document.getElementById('storage-title');
  const copy = document.getElementById('storage-copy');
  if(!dot || !title || !copy) return;
  dot.className = 'status-dot' + (status === 'online' ? ' online' : status === 'offline' ? ' offline' : '');
  title.textContent = status === 'online' ? 'Хранилище доступно' : status === 'offline' ? 'Нет связи с хранилищем' : 'Проверяем хранилище';
  copy.textContent = status === 'online' ? 'GitHub · ветка poems-data' : status === 'offline' ? 'Проверьте соединение или настройки' : 'Связь с архивом GitHub';
}

function showPoemError(message){
  const error = document.getElementById('poem-error');
  if(!error) return;
  error.textContent = message;
  error.style.display = 'block';
}

function clearPoemCyclesError(){
  const error = document.getElementById('poem-cycles-error');
  if(!error) return;
  error.textContent = '';
  error.style.display = 'none';
}
function showPoemCyclesError(message){
  const error = document.getElementById('poem-cycles-error');
  if(!error) return;
  error.textContent = message;
  error.style.display = 'block';
}
function getCyclesForPoem(poemId){
  if(!poemId || !cyclesLoaded) return [];
  return cycles.filter(cycle=>Array.isArray(cycle.poemIds) && cycle.poemIds.includes(poemId));
}
function poemCycleDescription(poemId){
  if(!cyclesLoaded) return cyclesLoadError ? 'Не удалось загрузить циклы' : 'Загрузка циклов…';
  const memberships = getCyclesForPoem(poemId);
  if(!memberships.length) return 'Вне циклов';
  if(memberships.length === 1) return 'Цикл: ' + (memberships[0].title || 'Без названия');
  return 'В циклах: ' + memberships.length;
}
function updatePoemCycleEditor(){
  const container = document.getElementById('poem-editor-cycles');
  if(!container) return;
  container.replaceChildren();
  if(!editingPoemId){
    container.textContent = 'Сохраните стихотворение, чтобы добавить его в цикл.';
    return;
  }
  if(!cyclesLoaded){
    container.textContent = cyclesLoadError ? 'Не удалось загрузить циклы.' : 'Загрузка циклов…';
    return;
  }
  const memberships = getCyclesForPoem(editingPoemId);
  if(!memberships.length){
    container.textContent = 'Вне циклов';
    return;
  }
  memberships.forEach(cycle=>{
    const entry = document.createElement('div');
    entry.className = 'poem-editor-cycle';
    entry.textContent = cycle.title || 'Без названия';
    container.append(entry);
  });
}

let editingPoemId = '';

function openPoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  editingPoemId = '';
  document.getElementById('poem-id').value = '';
  document.getElementById('poem-form-heading').textContent = 'Новое стихотворение';
  const now = new Date();
  document.getElementById('poem-date').value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0,10);
  document.getElementById('poem-status').value = 'published';
  initializeImageEditor('poems',null);
  document.getElementById('poem-delete').hidden = true;
  document.getElementById('poem-error').style.display = 'none';
  updatePoemCycleEditor();
  form.style.display = 'block';
  document.getElementById('poem-title').focus();
}
function closePoemForm(){
  cleanupUncommittedImageUploads('poems');
  const form = document.getElementById('poem-form');
  form.reset();
  form.style.display = 'none';
  editingPoemId = '';
  document.getElementById('poem-id').value = '';
  document.getElementById('poem-delete').hidden = true;
}
function startPoem(){
  showSection('poems');
  openPoemForm();
}
function editPoem(poem){
  showSection('poems');
  editingPoemId = poem.id;
  document.getElementById('poem-id').value = poem.id;
  document.getElementById('poem-form-heading').textContent = 'Редактировать стихотворение';
  document.getElementById('poem-title').value = poem.title || '';
  document.getElementById('poem-text').value = poem.text || '';
  document.getElementById('poem-date').value = poem.date || '';
  document.getElementById('poem-status').value = poem.status === 'draft' ? 'draft' : 'published';
  initializeImageEditor('poems',poem);
  document.getElementById('poem-delete').hidden = false;
  document.getElementById('poem-error').style.display = 'none';
  updatePoemCycleEditor();
  document.getElementById('poem-form').style.display = 'block';
  document.getElementById('poem-title').focus();
}
function showProseError(message){
  const error = document.getElementById('prose-error');
  if(!error) return;
  error.textContent = message;
  error.style.display = 'block';
}
function clearProseError(){
  const error = document.getElementById('prose-error');
  if(!error) return;
  error.textContent = '';
  error.style.display = 'none';
}
async function loadProse(){
  if(proseLoadPromise) return proseLoadPromise;
  proseLoadPromise = (async()=>{
    proseLoaded = false;
    renderProse();
    clearProseError();
    try{
      const response = await fetch('/api/prose');
      const result = await response.json();
      if(!response.ok) throw new Error(result.error || 'Не удалось загрузить прозу');
      if(!result || !Array.isArray(result.prose)) throw new Error('Сервер вернул некорректный список прозы');
      proseEntries = result.prose;
      proseLoaded = true;
      document.getElementById('prose-count').textContent = String(proseEntries.length);
      setStorageStatus('online');
      renderProse();
    }catch(error){
      proseLoaded = false;
      setStorageStatus('offline');
      showProseError(error.message);
      renderProse();
    }
  })().finally(()=>{proseLoadPromise = null;});
  return proseLoadPromise;
}
function proseTypeLabel(type){
  return ({story:'Рассказ',novel:'Роман',chapter:'Глава'})[type] || 'Произведение';
}
function proseStatusLabel(entry){
  return entry.status === 'draft' ? 'Черновик' : 'Опубликовано';
}
function setProseFilter(filter){
  if(!['all','published','draft'].includes(filter)) return;
  proseStatusFilter = filter;
  renderProse();
}
function setProseSearch(value){
  proseSearchTerm = value.trim().toLocaleLowerCase('ru');
  renderProse();
}
function renderProse(){
  const list = document.getElementById('prose-list');
  if(!list) return;
  list.replaceChildren();
  document.querySelectorAll('[data-prose-filter]').forEach(button=>{
    button.classList.toggle('active',button.dataset.proseFilter === proseStatusFilter);
  });
  const count = document.getElementById('prose-filter-count');
  if(!proseLoaded){
    if(count) count.textContent = '';
    const loading = document.createElement('div');
    loading.className = 'prose-empty';
    loading.textContent = 'Загружаем прозу…';
    list.append(loading);
    return;
  }
  if(proseEntries.length === 0){
    if(count) count.textContent = '0 / 0';
    const empty = document.createElement('div');
    empty.className = 'prose-empty';
    empty.textContent = 'Проза пока пуста';
    list.append(empty);
    return;
  }
  const visibleEntries = proseEntries.filter(entry=>{
    const matchesStatus = proseStatusFilter === 'all' || entry.status === proseStatusFilter;
    const matchesSearch = !proseSearchTerm || (entry.title || '').toLocaleLowerCase('ru').includes(proseSearchTerm);
    return matchesStatus && matchesSearch;
  });
  if(count) count.textContent = visibleEntries.length + ' / ' + proseEntries.length;
  if(!visibleEntries.length){
    const empty = document.createElement('div');
    empty.className = 'prose-empty';
    empty.textContent = 'Ничего не найдено. Измените фильтр или поисковый запрос.';
    list.append(empty);
    return;
  }
  visibleEntries.forEach(entry=>{
    const card = document.createElement('article');
    card.className = 'prose-card';
    const head = document.createElement('div');
    head.className = 'poem-item-head';
    const titleBlock = document.createElement('div');
    const type = document.createElement('div');
    type.className = 'prose-card-type';
    type.textContent = proseTypeLabel(entry.type);
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = entry.title || 'Без названия';
    const date = document.createElement('div');
    date.className = 'poem-item-date';
    date.textContent = formatPoemDate(entry.date);
    titleBlock.append(type,title,date);
    const status = document.createElement('span');
    status.className = 'poem-status' + (entry.status === 'draft' ? ' draft' : '');
    status.textContent = proseStatusLabel(entry);
    head.append(titleBlock,status);
    const snippet = document.createElement('div');
    snippet.className = 'poem-snippet';
    const summary = (entry.description || entry.text || '').trim();
    snippet.textContent = summary.length > 220 ? summary.slice(0,220) + '…' : summary;
    const actions = document.createElement('div');
    actions.className = 'poem-item-actions';
    const preview = document.createElement('button');
    preview.className = 'btn-secondary';
    preview.type = 'button';
    preview.textContent = 'Предпросмотр';
    preview.addEventListener('click',()=>openProsePreview(entry));
    const edit = document.createElement('button');
    edit.className = 'btn-secondary';
    edit.type = 'button';
    edit.textContent = 'Изменить';
    edit.addEventListener('click',()=>editProse(entry));
    const remove = document.createElement('button');
    remove.className = 'btn-danger';
    remove.type = 'button';
    remove.textContent = 'Удалить';
    remove.addEventListener('click',()=>deleteProse(entry.id,entry.title));
    actions.append(preview,edit,remove);
    card.append(head,snippet,actions);
    list.append(card);
  });
}
function openProseForm(){
  const form = document.getElementById('prose-form');
  form.reset();
  editingProseId = '';
  document.getElementById('prose-id').value = '';
  document.getElementById('prose-form-heading').textContent = 'Новая проза';
  const now = new Date();
  document.getElementById('prose-date').value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0,10);
  document.getElementById('prose-type').value = 'story';
  document.getElementById('prose-status').value = 'published';
  initializeImageEditor('prose',null);
  document.getElementById('prose-delete').hidden = true;
  clearProseError();
  form.style.display = 'block';
  document.getElementById('prose-title').focus();
}
function startProse(){
  showSection('prose');
  openProseForm();
}
function closeProseForm(){
  cleanupUncommittedImageUploads('prose');
  const form = document.getElementById('prose-form');
  form.reset();
  form.style.display = 'none';
  editingProseId = '';
  document.getElementById('prose-id').value = '';
  document.getElementById('prose-delete').hidden = true;
  clearProseError();
}
function editProse(entry){
  showSection('prose');
  editingProseId = entry.id;
  document.getElementById('prose-id').value = entry.id;
  document.getElementById('prose-form-heading').textContent = 'Редактировать произведение';
  document.getElementById('prose-title').value = entry.title || '';
  document.getElementById('prose-type').value = ['story','novel','chapter'].includes(entry.type) ? entry.type : 'story';
  document.getElementById('prose-description').value = entry.description || '';
  document.getElementById('prose-text').value = entry.text || '';
  document.getElementById('prose-date').value = entry.date || '';
  document.getElementById('prose-status').value = entry.status === 'draft' ? 'draft' : 'published';
  initializeImageEditor('prose',entry);
  document.getElementById('prose-delete').hidden = false;
  clearProseError();
  document.getElementById('prose-form').style.display = 'block';
  document.getElementById('prose-title').focus();
}
function fillProsePreview(entry){
  document.getElementById('prose-preview-title').textContent = entry.title || 'Без названия';
  document.getElementById('prose-preview-meta').textContent = proseTypeLabel(entry.type) + ' · ' + formatPoemDate(entry.date);
  document.getElementById('prose-preview-description').textContent = entry.description || '';
  document.getElementById('prose-preview-description').hidden = !entry.description;
  document.getElementById('prose-preview-body').textContent = entry.text || '';
  document.getElementById('prose-preview-status').textContent = proseStatusLabel(entry);
  const figure = document.getElementById('prose-preview-figure');
  const image = document.getElementById('prose-preview-image');
  const caption = document.getElementById('prose-preview-caption');
  const frame = image.parentElement;
  const source = safeImageSource(entry.image);
  image.onerror = ()=>{figure.hidden = true;resetImageFrameGeometry(frame);};
  image.onload = ()=>{applySavedImageEffects(image,entry,'prose');figure.hidden = false;};
  if(source){
    const resolvedSource = new URL(source,window.location.origin).href;
    if(image.src !== resolvedSource){resetImageFrameGeometry(frame);image.src = source;}
    applySavedImageEffects(image,entry,'prose');
    caption.querySelector('.image-caption-text').textContent = entry.imageCaption || '';
    caption.hidden = !entry.imageCaption && !caption.querySelector('.archive-meta-caption').textContent;
    figure.hidden = false;
  }else{
    resetImageFrameGeometry(frame);
    image.removeAttribute('src');
    figure.hidden = true;
  }
  document.getElementById('prose-preview').hidden = false;
}
function previewProseForm(){
  fillProsePreview({
    title:document.getElementById('prose-title').value.trim(),
    type:document.getElementById('prose-type').value,
    description:document.getElementById('prose-description').value.trim(),
    text:document.getElementById('prose-text').value,
    date:document.getElementById('prose-date').value,
    status:document.getElementById('prose-status').value,
    ...getImageEditorData('prose')
  });
}
function openProsePreview(entry){
  fillProsePreview(entry);
}
function closeProsePreview(){
  document.getElementById('prose-preview').hidden = true;
}
async function saveProse(event){
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector('[type="submit"]:focus') || event.submitter;
  const forcedStatus = submitButton && submitButton.dataset.saveStatus;
  const entry = {
    title:document.getElementById('prose-title').value.trim(),
    type:document.getElementById('prose-type').value,
    description:document.getElementById('prose-description').value.trim(),
    text:document.getElementById('prose-text').value.trim(),
    date:document.getElementById('prose-date').value,
    status:forcedStatus || document.getElementById('prose-status').value,
    ...getImageEditorData('prose')
  };
  const payload = editingProseId ? {action:'update',id:editingProseId,prose:entry} : {action:'create',prose:entry};
  const buttons = form.querySelectorAll('[type="submit"]');
  buttons.forEach(button=>button.disabled = true);
  try{
    const response = await fetch('/api/prose',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить произведение');
    if(!result || !Array.isArray(result.prose)) throw new Error('Сервер вернул некорректный список прозы');
    proseEntries = result.prose;
    proseLoaded = true;
    document.getElementById('prose-count').textContent = String(proseEntries.length);
    setStorageStatus('online');
    renderProse();
    const imageCleanupErrors = await finalizeImageEditorSave('prose');
    closeProseForm();
    if(imageCleanupErrors.length) showProseError('Запись сохранена. Не удалось удалить старое изображение: ' + imageCleanupErrors.join('; '));
  }catch(error){
    setStorageStatus('offline');
    showProseError(error.message);
  }finally{
    buttons.forEach(button=>button.disabled = false);
  }
}
async function deleteProse(id,title){
  if(!window.confirm('Удалить произведение «' + (title || 'Без названия') + '»? Это действие нельзя отменить.')) return;
  try{
    const response = await fetch('/api/prose',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'delete',id})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось удалить произведение');
    if(!result || !Array.isArray(result.prose)) throw new Error('Сервер вернул некорректный список прозы');
    proseEntries = result.prose;
    proseLoaded = true;
    document.getElementById('prose-count').textContent = String(proseEntries.length);
    setStorageStatus('online');
    renderProse();
    if(editingProseId === id) closeProseForm();
    closeProsePreview();
    clearProseError();
  }catch(error){
    showProseError(error.message);
  }
}
function deleteEditingProse(){
  if(!editingProseId) return;
  const entry = proseEntries.find(item=>item.id === editingProseId);
  deleteProse(editingProseId,entry && entry.title);
}

function formatPoemDate(date){
  if(!date) return 'Дата не указана';
  const parts = date.split('-');
  return parts.length === 3 ? parts[2] + '.' + parts[1] + '.' + parts[0] : date;
}
function poemStatusLabel(poem){
  return poem.status === 'draft' ? 'Черновик' : 'Опубликовано';
}
function safeImageSource(value){
  const source = (value || '').trim();
  if(!source) return '';
  try{
    const parsed = new URL(source, window.location.origin);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? source : '';
  }catch{
    return '';
  }
}
function applySavedImageEffects(image,record,contentKind='poem'){
  const effect = ['none','fade','darken','scale','zoom','glow','archive'].includes(record.imageEffect) ? (record.imageEffect === 'zoom' ? 'scale' : record.imageEffect) : 'none';
  const position = ['center','top','bottom','left','right'].includes(record.imagePosition) ? record.imagePosition : 'center';
  const hover = ['none','scale','zoom','glow'].includes(record.imageHover) ? (record.imageHover === 'zoom' ? 'scale' : record.imageHover) : 'none';
  const baseScale = Number.isFinite(Number(record.imageScale)) ? Number(record.imageScale) : 100;
  const intensity = (Number.isFinite(Number(record.imageIntensity)) ? Number(record.imageIntensity) : 50) / 100;
  const positions = {center:'50% 50%',top:'50% 0%',bottom:'50% 100%',left:'0% 50%',right:'100% 50%'};
  image.style.objectPosition = positions[position];
  image.style.opacity = effect === 'fade' ? String(.4 + intensity * .6) : '1';
  const darken = effect === 'darken' ? intensity * .65 : 0;
  image.style.filter = 'brightness(' + Math.max(0,1 - darken) + ')';
  const scale = baseScale / 100 * (effect === 'scale' ? 1 + intensity * .25 : 1);
  image.style.transform = 'scale(' + scale + ')';
  image.style.transformOrigin = positions[position];
  syncImageFrameGeometry(image,record,scale);
  image.style.boxShadow = effect === 'glow' ? '0 0 ' + (8 + intensity * 30) + 'px rgba(238,35,73,' + (.15 + intensity * .65) + ')' : 'none';
  image.style.transition = 'opacity .35s,transform .35s,filter .35s,box-shadow .35s';
  image.onmouseenter = ()=>{
    if(hover === 'scale'){
      image.style.transform = 'scale(' + (scale * 1.1) + ')';
      syncImageFrameGeometry(image,record,scale * 1.1);
    }
    if(hover === 'glow') image.style.boxShadow = '0 0 28px rgba(238,35,73,.72)';
  };
  image.onmouseleave = ()=>{
    image.style.transform = 'scale(' + scale + ')';
    syncImageFrameGeometry(image,record,scale);
    image.style.boxShadow = effect === 'glow' ? '0 0 ' + (8 + intensity * 30) + 'px rgba(238,35,73,' + (.15 + intensity * .65) + ')' : 'none';
  };
  renderImageDarkening(image.parentElement,record);
  renderArchiveMarkup(image.parentElement,record,contentKind);
  renderImageWatermark(image.parentElement,record);
}
function fillPoemPreview(poem){
  document.getElementById('preview-title').textContent = poem.title || 'Без названия';
  document.getElementById('preview-date').textContent = formatPoemDate(poem.date);
  document.getElementById('preview-body').textContent = poem.text || '';
  document.getElementById('preview-status').textContent = poemStatusLabel(poem);
  const figure = document.getElementById('preview-figure');
  const image = document.getElementById('preview-image');
  const frame = image.parentElement;
  const source = safeImageSource(poem.image);
  image.onerror = ()=>{figure.hidden = true;resetImageFrameGeometry(frame);};
  image.onload = ()=>{applySavedImageEffects(image,poem,'poem');figure.hidden = false;};
  if(source){
    const resolvedSource = new URL(source,window.location.origin).href;
    if(image.src !== resolvedSource){resetImageFrameGeometry(frame);image.src = source;}
    applySavedImageEffects(image,poem,'poem');
    figure.hidden = false;
    const caption = typeof poem.imageCaption === 'string' ? poem.imageCaption : (poem.caption || '');
    const captionElement = document.getElementById('preview-caption');
    captionElement.querySelector('.image-caption-text').textContent = caption;
    captionElement.hidden = !caption && !captionElement.querySelector('.archive-meta-caption').textContent;
  }else{
    resetImageFrameGeometry(frame);
    image.removeAttribute('src');
    figure.hidden = true;
  }
  document.getElementById('poem-preview').hidden = false;
}
function previewPoemForm(){
  const title = document.getElementById('poem-title').value.trim();
  const text = document.getElementById('poem-text').value.trim();
  if(!title || !text){
    showPoemError('Укажите название и текст, чтобы открыть предпросмотр.');
    return;
  }
  document.getElementById('poem-error').style.display = 'none';
  fillPoemPreview({
    title,
    text,
    date:document.getElementById('poem-date').value,
    status:document.getElementById('poem-status').value,
    image:document.getElementById('poem-image').value,
    caption:document.getElementById('poem-caption').value.trim(),
    ...getImageEditorData('poems')
  });
}
function openPoemPreview(poem){
  fillPoemPreview(poem);
}
function closePoemPreview(){
  document.getElementById('poem-preview').hidden = true;
}
async function savePoem(event){
  event.preventDefault();
  const form = event.currentTarget;
  const title = document.getElementById('poem-title').value.trim();
  const text = document.getElementById('poem-text').value.trim();
  if(!title || !text) return;
  const submitButton = form.querySelector('[type="submit"]:focus') || event.submitter;
  const forcedStatus = submitButton && submitButton.dataset.saveStatus;
  const poem = {
    title,
    text,
    date:document.getElementById('poem-date').value,
    status:forcedStatus || document.getElementById('poem-status').value,
    ...getImageEditorData('poems'),
    caption:document.getElementById('poem-caption').value.trim()
  };
  const payload = editingPoemId
    ? {action:'update',id:editingPoemId,poem}
    : {action:'create',poem};
  const saveButtons = form.querySelectorAll('[type="submit"]');
  saveButtons.forEach(button=>button.disabled = true);
  try{
    const response = await fetch('/api/poems', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить стихотворение');
    poems = result.poems;
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
    const imageCleanupErrors = await finalizeImageEditorSave('poems');
    closePoemForm();
    if(imageCleanupErrors.length) showPoemError('Стихотворение сохранено. Не удалось удалить старое изображение: ' + imageCleanupErrors.join('; '));
    else document.getElementById('poem-error').style.display = 'none';
  }catch(error){
    setStorageStatus('offline');
    showPoemError(error.message);
  }finally{
    saveButtons.forEach(button=>button.disabled = false);
  }
}
async function deletePoem(id,title){
  if(!window.confirm('Удалить стихотворение «' + (title || 'Без названия') + '»? Это действие нельзя отменить.')) return;
  try{
    const response = await fetch('/api/poems', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'delete',id})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось удалить стихотворение');
    poems = result.poems;
    poemsLoaded = true;
    setStorageStatus('online');
    try{
      const cycleResponse = await fetch('/api/cycles');
      const cycleResult = await cycleResponse.json();
      if(!cycleResponse.ok) throw new Error(cycleResult.error || 'Не удалось обновить циклы');
      cycles = cycleResult.cycles;
      cyclesLoaded = true;
      cyclesLoadError = '';
      renderCycles();
      clearPoemCyclesError();
    }catch(error){
      cyclesLoaded = false;
      cyclesLoadError = error.message;
      showPoemCyclesError(error.message);
    }
    renderPoems();
    updatePoemCycleEditor();
    if(editingPoemId === id) closePoemForm();
    closePoemPreview();
    document.getElementById('poem-error').style.display = 'none';
  }catch(error){
    showPoemError(error.message);
  }
}
function deleteEditingPoem(){
  if(!editingPoemId) return;
  const poem = poems.find(item=>item.id === editingPoemId);
  deletePoem(editingPoemId,poem && poem.title);
}

function setPoemCycleFilter(filter){
  if(!['all','outside','inside'].includes(filter)) return;
  poemCycleFilter = filter;
  renderPoems();
}

function renderPoems(){
  const list = document.getElementById('poem-list');
  list.replaceChildren();
  document.getElementById('poem-count').textContent = String(poems.length);
  renderRecentChanges();
  document.querySelectorAll('[data-poem-filter]').forEach(button=>{
    button.classList.toggle('active',button.dataset.poemFilter === poemCycleFilter);
  });
  if(poems.length === 0){
    const filterCount = document.getElementById('poem-filter-count');
    if(filterCount) filterCount.textContent = '0 / 0';
    const empty = document.createElement('div');
    empty.className = 'item';
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = 'Пока нет стихотворений';
    const message = document.createElement('div');
    message.className = 'item-meta empty-copy';
    message.textContent = 'Добавьте первое стихотворение, чтобы начать наполнять архив.';
    empty.append(title,message);
    list.append(empty);
    return;
  }
  const visiblePoems = !cyclesLoaded || poemCycleFilter === 'all'
    ? poems
    : poems.filter(poem=>{
      const inCycles = getCyclesForPoem(poem.id).length > 0;
      return poemCycleFilter === 'inside' ? inCycles : !inCycles;
    });
  const filterCount = document.getElementById('poem-filter-count');
  if(filterCount) filterCount.textContent = visiblePoems.length + ' / ' + poems.length;
  if(!visiblePoems.length){
    const empty = document.createElement('div');
    empty.className = 'item item-meta empty-copy';
    empty.textContent = 'В этой категории пока нет стихотворений. Переключите фильтр или выберите «Все».';
    list.append(empty);
    return;
  }
  visiblePoems.forEach(poem=>{
    const item = document.createElement('article');
    item.className = 'item';
    const head = document.createElement('div');
    head.className = 'poem-item-head';
    const titleBlock = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = poem.title || 'Без названия';
    const date = document.createElement('div');
    date.className = 'poem-item-date';
    date.textContent = formatPoemDate(poem.date);
    titleBlock.append(title,date);
    const status = document.createElement('span');
    status.className = 'poem-status' + (poem.status === 'draft' ? ' draft' : '');
    status.textContent = poemStatusLabel(poem);
    head.append(titleBlock,status);
    const snippet = document.createElement('div');
    snippet.className = 'poem-snippet';
    const trimmedText = (poem.text || '').trim();
    snippet.textContent = trimmedText.length > 220 ? trimmedText.slice(0,220) + '…' : trimmedText;
    const cycleInfo = document.createElement('div');
    const poemCycles = getCyclesForPoem(poem.id);
    cycleInfo.className = 'poem-cycle-info' + (poemCycles.length ? ' has-cycles' : '');
    cycleInfo.textContent = poemCycleDescription(poem.id);
    const actions = document.createElement('div');
    actions.className = 'poem-item-actions';
    const preview = document.createElement('button');
    preview.className = 'btn-secondary';
    preview.type = 'button';
    preview.textContent = 'Предпросмотр';
    preview.addEventListener('click',()=>openPoemPreview(poem));
    const edit = document.createElement('button');
    edit.className = 'btn-secondary';
    edit.type = 'button';
    edit.textContent = 'Изменить';
    edit.addEventListener('click',()=>editPoem(poem));
    const remove = document.createElement('button');
    remove.className = 'btn-danger';
    remove.type = 'button';
    remove.textContent = 'Удалить';
    remove.addEventListener('click',()=>deletePoem(poem.id,poem.title));
    actions.append(preview,edit,remove);
    item.append(head,snippet,cycleInfo,actions);
    list.append(item);
  });
}

function renderRecentChanges(){
  const list = document.getElementById('recent-list');
  list.replaceChildren();
  if(!poems.length){
    const empty = document.createElement('div');
    empty.className = 'empty-note';
    empty.textContent = poemsLoaded ? 'Записей пока нет. Первое стихотворение можно добавить в разделе «Стихи».' : 'Загружаем архив…';
    list.append(empty);
    return;
  }
  poems.slice(-4).reverse().forEach(poem=>{
    const entry = document.createElement('div');
    entry.className = 'recent-entry';
    const icon = document.createElement('span');
    icon.className = 'recent-icon';
    icon.textContent = '✎';
    const body = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'recent-title';
    title.textContent = poem.title;
    const copy = document.createElement('div');
    copy.className = 'recent-copy';
    copy.textContent = poem.text;
    body.append(title,copy);
    entry.append(icon,body);
    list.append(entry);
  });
}

async function loadPoemsForCycles(){
  if(poemsLoaded) return;
  const response = await fetch('/api/poems');
  if(!response.ok) throw new Error('Не удалось загрузить список стихотворений');
  poems = await response.json();
  poemsLoaded = true;
  renderPoems();
}

async function loadCycles(){
  if(cyclesLoaded) return;
  if(cyclesLoadPromise) return cyclesLoadPromise;
  cyclesLoadError = '';
  cyclesLoadPromise = (async()=>{
    try{
      await loadPoemsForCycles();
      const response = await fetch('/api/cycles');
      const result = await response.json();
      if(!response.ok) throw new Error(result.error || 'Не удалось загрузить циклы');
      cycles = result.cycles;
      cyclesLoaded = true;
      cyclesLoadError = '';
      renderCycles();
      renderPoems();
      updatePoemCycleEditor();
      clearPoemCyclesError();
    }catch(error){
      cyclesLoadError = error.message;
      showCycleError(error.message);
      showPoemCyclesError(error.message);
      renderPoems();
      updatePoemCycleEditor();
    }finally{
      cyclesLoadPromise = null;
    }
  })();
  return cyclesLoadPromise;
}

function clearCycleError(){
  const error = document.getElementById('cycle-error');
  error.textContent = '';
  error.style.display = 'none';
}
function showCycleError(message){
  const error = document.getElementById('cycle-error');
  error.textContent = message;
  error.style.display = 'block';
}
async function startCycle(){
  showSection('cycles');
  await openCycleForm();
}
async function openCycleForm(){
  await loadCycles();
  const form = document.getElementById('cycle-form');
  form.reset();
  editingCycleId = '';
  editingCyclePoemIds = [];
  document.getElementById('cycle-id').value = '';
  document.getElementById('cycle-form-heading').textContent = 'Новый цикл';
  document.getElementById('cycle-status').value = 'draft';
  initializeImageEditor('cycles',null);
  document.getElementById('cycle-delete').hidden = true;
  clearCycleError();
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
  form.style.display = 'block';
  document.getElementById('cycle-title').focus();
}
function closeCycleForm(){
  cleanupUncommittedImageUploads('cycles');
  const form = document.getElementById('cycle-form');
  form.reset();
  form.style.display = 'none';
  editingCycleId = '';
  editingCyclePoemIds = [];
  document.getElementById('cycle-id').value = '';
  document.getElementById('cycle-delete').hidden = true;
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function editCycle(cycle){
  showSection('cycles');
  editingCycleId = cycle.id;
  editingCyclePoemIds = [...(cycle.poemIds || [])];
  document.getElementById('cycle-id').value = cycle.id;
  document.getElementById('cycle-form-heading').textContent = 'Редактировать цикл';
  document.getElementById('cycle-title').value = cycle.title || '';
  document.getElementById('cycle-description').value = cycle.description || '';
  document.getElementById('cycle-status').value = cycle.status === 'published' ? 'published' : 'draft';
  initializeImageEditor('cycles',cycle);
  document.getElementById('cycle-delete').hidden = false;
  clearCycleError();
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
  document.getElementById('cycle-form').style.display = 'block';
  document.getElementById('cycle-title').focus();
}
function renderCyclePoemPicker(){
  const picker = document.getElementById('cycle-poem-picker');
  const addButton = document.getElementById('cycle-add-poem');
  if(!picker || !addButton) return;
  picker.replaceChildren();
  const available = poems.filter(poem=>poem.id && !editingCyclePoemIds.includes(poem.id));
  if(!available.length){
    const option = document.createElement('option');
    option.value = '';
    option.textContent = poems.length ? 'Все стихотворения уже добавлены' : 'Сначала добавьте стихотворение';
    picker.append(option);
    addButton.disabled = true;
    return;
  }
  available.forEach(poem=>{
    const option = document.createElement('option');
    option.value = poem.id;
    option.textContent = poem.title || 'Без названия';
    picker.append(option);
  });
  addButton.disabled = false;
}
function addPoemToCycle(){
  const id = document.getElementById('cycle-poem-picker').value;
  if(!id || editingCyclePoemIds.includes(id)) return;
  if(!poems.some(poem=>poem.id === id)) return;
  editingCyclePoemIds.push(id);
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function renderSelectedCyclePoems(){
  const list = document.getElementById('cycle-selected-poems');
  if(!list) return;
  list.replaceChildren();
  if(!editingCyclePoemIds.length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'В цикле пока нет стихотворений.';
    list.append(empty);
    return;
  }
  editingCyclePoemIds.forEach((id,index)=>{
    const poem = poems.find(item=>item.id === id);
    const row = document.createElement('div');
    row.className = 'cycle-selected-row';
    const order = document.createElement('span');
    order.className = 'cycle-order';
    order.textContent = String(index + 1).padStart(2,'0');
    const title = document.createElement('span');
    title.className = 'cycle-poem-name' + (poem ? '' : ' cycle-poem-missing');
    title.textContent = poem ? poem.title : 'Стихотворение не найдено — удалите его из цикла';
    const controls = document.createElement('div');
    controls.className = 'cycle-order-actions';
    const moveUp = document.createElement('button');
    moveUp.type = 'button';
    moveUp.title = 'Переместить вверх';
    moveUp.setAttribute('aria-label','Переместить выше');
    moveUp.textContent = '↑';
    moveUp.disabled = index === 0;
    moveUp.addEventListener('click',()=>moveCyclePoem(index,-1));
    const moveDown = document.createElement('button');
    moveDown.type = 'button';
    moveDown.title = 'Переместить вниз';
    moveDown.setAttribute('aria-label','Переместить ниже');
    moveDown.textContent = '↓';
    moveDown.disabled = index === editingCyclePoemIds.length - 1;
    moveDown.addEventListener('click',()=>moveCyclePoem(index,1));
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.title = 'Убрать из цикла';
    remove.setAttribute('aria-label','Убрать стихотворение из цикла');
    remove.textContent = '×';
    remove.addEventListener('click',()=>removePoemFromCycle(index));
    controls.append(moveUp,moveDown,remove);
    row.append(order,title,controls);
    list.append(row);
  });
}
function moveCyclePoem(index,offset){
  const destination = index + offset;
  if(destination < 0 || destination >= editingCyclePoemIds.length) return;
  const updated = [...editingCyclePoemIds];
  const [id] = updated.splice(index,1);
  updated.splice(destination,0,id);
  editingCyclePoemIds = updated;
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function removePoemFromCycle(index){
  editingCyclePoemIds.splice(index,1);
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
async function saveCycle(event){
  event.preventDefault();
  const form = event.currentTarget;
  const cycle = {
    title:document.getElementById('cycle-title').value.trim(),
    description:document.getElementById('cycle-description').value.trim(),
    status:document.getElementById('cycle-status').value,
    ...getImageEditorData('cycles'),
    cover:document.getElementById('cycle-cover').value.trim(),
    poemIds:[...editingCyclePoemIds]
  };
  const payload = editingCycleId
    ? {action:'update',id:editingCycleId,cycle}
    : {action:'create',cycle};
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  try{
    const response = await fetch('/api/cycles', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить цикл');
    cycles = result.cycles;
    cyclesLoaded = true;
    renderCycles();
    renderPoems();
    updatePoemCycleEditor();
    const imageCleanupErrors = await finalizeImageEditorSave('cycles');
    closeCycleForm();
    clearCycleError();
    if(imageCleanupErrors.length) showCycleError('Цикл сохранён. Не удалось удалить старое изображение: ' + imageCleanupErrors.join('; '));
  }catch(error){
    showCycleError(error.message);
  }finally{
    button.disabled = false;
  }
}
function deleteEditingCycle(){
  if(!editingCycleId) return;
  const cycle = cycles.find(item=>item.id === editingCycleId);
  deleteCycle(editingCycleId,cycle && cycle.title);
}
async function deleteCycle(id,title){
  if(!window.confirm('Удалить цикл «' + (title || 'Без названия') + '»? Сами стихотворения останутся в архиве.')) return;
  try{
    const response = await fetch('/api/cycles', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'delete',id})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось удалить цикл');
    cycles = result.cycles;
    cyclesLoaded = true;
    renderCycles();
    renderPoems();
    updatePoemCycleEditor();
    if(editingCycleId === id) closeCycleForm();
    closeCyclePreview();
    clearCycleError();
  }catch(error){
    showCycleError(error.message);
  }
}
function cyclePoemCountLabel(count){
  const lastTwo = count % 100;
  const last = count % 10;
  if(lastTwo >= 11 && lastTwo <= 14) return count + ' стихотворений';
  if(last === 1) return count + ' стихотворение';
  if(last >= 2 && last <= 4) return count + ' стихотворения';
  return count + ' стихотворений';
}
function renderCycles(){
  const list = document.getElementById('cycle-list');
  list.replaceChildren();
  document.getElementById('cycle-count').textContent = String(cycles.length);
  if(!cycles.length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'Циклов пока нет. Создайте первый цикл и добавьте в него стихотворения из архива.';
    list.append(empty);
    return;
  }
  cycles.forEach(cycle=>{
    const card = document.createElement('article');
    card.className = 'cycle-card';
    const cover = document.createElement('img');
    cover.className = 'cycle-card-cover';
    cover.alt = '';
    const source = safeImageSource(cycle.cover);
    if(source){
      cover.src = source;
      cover.onerror = ()=>{cover.hidden = true;};
    }else{
      cover.hidden = true;
    }
    const body = document.createElement('div');
    body.className = 'cycle-card-body';
    const head = document.createElement('div');
    head.className = 'cycle-card-head';
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = cycle.title || 'Без названия';
    const status = document.createElement('span');
    status.className = 'poem-status' + (cycle.status === 'draft' ? ' draft' : '');
    status.textContent = cycle.status === 'published' ? 'Опубликован' : 'Черновик';
    head.append(title,status);
    const description = document.createElement('p');
    description.className = 'cycle-card-description';
    description.textContent = cycle.description || 'Описание не добавлено.';
    const count = document.createElement('div');
    count.className = 'cycle-card-count';
    count.textContent = cyclePoemCountLabel((cycle.poemIds || []).length);
    const actions = document.createElement('div');
    actions.className = 'cycle-card-actions';
    const preview = document.createElement('button');
    preview.className = 'btn-secondary';
    preview.type = 'button';
    preview.textContent = 'Предпросмотр';
    preview.addEventListener('click',()=>openCyclePreview(cycle));
    const edit = document.createElement('button');
    edit.className = 'btn-secondary';
    edit.type = 'button';
    edit.textContent = 'Изменить';
    edit.addEventListener('click',()=>editCycle(cycle));
    const remove = document.createElement('button');
    remove.className = 'btn-danger';
    remove.type = 'button';
    remove.textContent = 'Удалить';
    remove.addEventListener('click',()=>deleteCycle(cycle.id,cycle.title));
    actions.append(preview,edit,remove);
    body.append(head,description,count,actions);
    card.append(cover,body);
    list.append(card);
  });
}
function fillCyclePreview(cycle){
  document.getElementById('cycle-preview-title').textContent = cycle.title || 'Без названия';
  document.getElementById('cycle-preview-description').textContent = cycle.description || '';
  document.getElementById('cycle-preview-status').textContent = cycle.status === 'published' ? 'Опубликован' : 'Черновик';
  const cover = document.getElementById('cycle-preview-cover');
  const figure = document.getElementById('cycle-preview-figure');
  const frame = cover.parentElement;
  const source = safeImageSource(cycle.image || cycle.cover);
  cover.onerror = ()=>{cover.hidden = true;figure.hidden = true;resetImageFrameGeometry(frame);};
  cover.onload = ()=>{applySavedImageEffects(cover,cycle,'cycle');figure.hidden = false;};
  if(source){
    const resolvedSource = new URL(source,window.location.origin).href;
    if(cover.src !== resolvedSource){resetImageFrameGeometry(frame);cover.src = source;}
    cover.hidden = false;
    applySavedImageEffects(cover,cycle,'cycle');
    figure.hidden = false;
    const caption = document.getElementById('cycle-preview-caption');
    caption.querySelector('.image-caption-text').textContent = cycle.imageCaption || '';
    caption.hidden = !cycle.imageCaption && !caption.querySelector('.archive-meta-caption').textContent;
  }else{
    resetImageFrameGeometry(frame);
    cover.removeAttribute('src');
    cover.hidden = true;
    figure.hidden = true;
  }
  const list = document.getElementById('cycle-preview-poems');
  list.replaceChildren();
  (cycle.poemIds || []).forEach((id,index)=>{
    const poem = poems.find(item=>item.id === id);
    const entry = document.createElement('article');
    entry.className = 'cycle-preview-poem';
    const title = document.createElement('strong');
    title.textContent = String(index + 1).padStart(2,'0') + '  /  ' + (poem ? poem.title : 'Стихотворение не найдено');
    entry.append(title);
    if(poem){
      const excerpt = document.createElement('p');
      const text = (poem.text || '').trim();
      excerpt.textContent = text.length > 260 ? text.slice(0,260) + '…' : text;
      entry.append(excerpt);
    }
    list.append(entry);
  });
  if(!(cycle.poemIds || []).length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'В цикле пока нет стихотворений.';
    list.append(empty);
  }
  document.getElementById('cycle-preview').hidden = false;
}
function previewCycleForm(){
  const title = document.getElementById('cycle-title').value.trim();
  if(!title){
    showCycleError('Добавьте название, чтобы открыть предпросмотр.');
    return;
  }
  clearCycleError();
  fillCyclePreview({
    title,
    description:document.getElementById('cycle-description').value.trim(),
    status:document.getElementById('cycle-status').value,
    ...getImageEditorData('cycles'),
    cover:document.getElementById('cycle-cover').value.trim(),
    poemIds:[...editingCyclePoemIds]
  });
}
function openCyclePreview(cycle){
  fillCyclePreview(cycle);
}
function closeCyclePreview(){
  document.getElementById('cycle-preview').hidden = true;
}

async function login(){
  const user = document.getElementById('user').value;
  const pass = document.getElementById('pass').value;
  const error = document.getElementById('error');
  try{
    const response = await fetch('/api/auth/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:user,password:pass})
    });
    if(!response.ok){
      error.textContent = response.status === 429 ? 'Слишком много попыток. Попробуйте позже.' : 'Неверный логин или пароль';
      error.style.display='block';
      return;
    }
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    error.style.display='none';
    document.getElementById('pass').value='';
    loadPoems();
  }catch{
    error.textContent = 'Не удалось выполнить вход. Попробуйте ещё раз.';
    error.style.display='block';
  }
}

async function restoreSession(){
  try{
    const response = await fetch('/api/auth/session');
    if(!response.ok) return;
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    loadPoems();
  }catch{}
}

async function logout(){
  try{
    await fetch('/api/auth/logout', {method:'POST'});
  }catch{
    // Return to the login screen even if the request fails.
  }finally{
    document.getElementById('app').style.display='none';
    document.getElementById('login').style.display='flex';
    document.getElementById('pass').value='';
  }
}

function showSection(id){
  const button = document.querySelector('.nav-link[data-view="' + id + '"]');
  show(id,button);
}

function show(id,button){
  document.querySelectorAll('.section').forEach(section=>section.classList.remove('active'));
  const section = document.getElementById(id);
  if(!section) return;
  section.classList.add('active');
  document.querySelectorAll('.nav-link[data-view]').forEach(link=>link.classList.remove('active'));
  const activeButton = button || document.querySelector('.nav-link[data-view="' + id + '"]');
  if(activeButton) activeButton.classList.add('active');
  document.getElementById('view-title').textContent = viewNames[id] || 'Архив';
  if(id === 'cycles' || id === 'poems') loadCycles();
  if(id === 'prose') loadProse();
}

mountAllImageEditors();
document.querySelectorAll('.preview-figure img, .cycle-preview-figure img, #image-effect-preview-image').forEach(image=>{image.draggable=false;});
document.addEventListener('contextmenu',event=>{
  if(event.target instanceof HTMLImageElement && (event.target.closest('.image-editor-preview') || event.target.id === 'image-effect-preview-image' || event.target.closest('.preview-figure') || event.target.closest('.cycle-preview-figure'))){
    event.preventDefault();
  }
});
document.addEventListener('dragstart',event=>{
  if(event.target instanceof HTMLImageElement && (event.target.closest('.image-editor-preview') || event.target.id === 'image-effect-preview-image' || event.target.closest('.preview-figure') || event.target.closest('.cycle-preview-figure'))){
    event.preventDefault();
  }
});
restoreSession();
</script>
</body>
</html>
`;

const server = http.createServer((req, res) => {

  if(req.url === '/api/auth/login' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    const ip = getClientIp(req);
    const attempt = getLoginAttempt(ip);
    if(attempt.count >= LOGIN_MAX_ATTEMPTS){
      res.setHeader('Retry-After', Math.ceil((LOGIN_WINDOW_MS - (Date.now() - attempt.windowStartedAt)) / 1000));
      sendJson(res, 429, {error:'Слишком много попыток входа. Попробуйте позже.'});
      return;
    }

    if(!process.env.ADMIN_USERNAME || !adminPasswordVerifier || getSessionPassword().length < 32){
      sendJson(res, 503, {error:'Авторизация не настроена'});
      return;
    }

    readRequestBody(req).then(async body=>{
      let credentials;
      try{
        credentials = JSON.parse(body);
      }catch{
        attempt.count++;
        sendJson(res, 400, {error:'Некорректный запрос'});
        return;
      }

      const username = typeof credentials.username === 'string' ? credentials.username : '';
      const password = typeof credentials.password === 'string' ? credentials.password : '';
      if(Buffer.byteLength(username) > 256 || Buffer.byteLength(password) > 1024){
        attempt.count++;
        sendJson(res, 401, {error:'Неверный логин или пароль'});
        return;
      }
      const passwordMatches = await verifyAdminPassword(password);
      if(username !== process.env.ADMIN_USERNAME || !passwordMatches){
        attempt.count++;
        if(attempt.count >= LOGIN_MAX_ATTEMPTS){
          res.setHeader('Retry-After', Math.ceil((LOGIN_WINDOW_MS - (Date.now() - attempt.windowStartedAt)) / 1000));
          sendJson(res, 429, {error:'Слишком много попыток входа. Попробуйте позже.'});
        }else{
          sendJson(res, 401, {error:'Неверный логин или пароль'});
        }
        return;
      }

      loginAttempts.delete(ip);
      const session = await sealData({username}, {password:getSessionPassword(), ttl:SESSION_TTL_SECONDS});
      setSessionCookie(res, session);
      sendJson(res, 200, {ok:true});
    }).catch(()=>{
      attempt.count++;
      sendJson(res, 400, {error:'Не удалось обработать запрос'});
    });
    return;
  }

  if(req.url === '/api/auth/session' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {authenticated:false});
        return;
      }
      sendJson(res, 200, {authenticated:true});
    }).catch(()=>sendJson(res, 401, {authenticated:false}));
    return;
  }

  if(req.url === '/api/auth/logout' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    setSessionCookie(res, '', 0);
    sendJson(res, 200, {ok:true});
    return;
  }

  if(req.url === '/api/poems' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readPoemsFromGitHub().then(({poems})=>{
        sendJson(res, 200, poems);
      }).catch(error=>sendGitHubError(res, error, 'read'));
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/poems' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readRequestBody(req).then(body=>{
        let payload;
        try{
          payload = JSON.parse(body);
        }catch{
          sendJson(res, 400, {error:'Некорректный JSON'});
          return;
        }

        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res, 400, {error:'Ожидался объект стихотворения'});
          return;
        }

        const action = payload.action || 'create';
        if(action === 'create'){
          const input = payload.poem && typeof payload.poem === 'object' && !Array.isArray(payload.poem) ? payload.poem : payload;
          const validation = validatePoem(input);
          if(validation.error){
            sendJson(res, 400, {error:validation.error});
            return;
          }
          const newPoem = {...validation.poem,id:crypto.randomUUID()};
          queuePoemMutation(poems=>[...poems,newPoem],'Create poem from admin panel').then(poems=>{
            sendJson(res, 201, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        if(action === 'update'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          const input = payload.poem;
          if(!id || !input || typeof input !== 'object' || Array.isArray(input)){
            sendJson(res, 400, {error:'Не указано стихотворение для изменения'});
            return;
          }
          const validation = validatePoem(input);
          if(validation.error){
            sendJson(res, 400, {error:validation.error});
            return;
          }
          queuePoemMutation(poems=>{
            const index = poems.findIndex((poem,position)=>getPoemId(poem,position) === id);
            if(index < 0){
              const error = new Error('Poem not found');
              error.code = 'POEM_NOT_FOUND';
              throw error;
            }
            const updated = poems.slice();
            updated[index] = {...updated[index],...validation.poem,...preserveOmittedImagePresentation(updated[index],input),id:getPoemId(updated[index],index)};
            return updated;
          },'Edit poem from admin panel').then(poems=>{
            sendJson(res, 200, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        if(action === 'delete'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          if(!id){
            sendJson(res, 400, {error:'Не указано стихотворение для удаления'});
            return;
          }
          queuePoemDeletionWithCycleCleanup(id).then(poems=>{
            sendJson(res, 200, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        sendJson(res, 400, {error:'Неизвестное действие со стихотворением'});
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res, status, {error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/cycles' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readCyclesFromGitHub().then(({cycles})=>{
        sendJson(res, 200, {cycles});
      }).catch(error=>sendGitHubError(res,error,'read'));
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/cycles' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readRequestBody(req).then(async body=>{
        let payload;
        try{
          payload = JSON.parse(body);
        }catch{
          sendJson(res, 400, {error:'Некорректный JSON'});
          return;
        }

        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res, 400, {error:'Ожидался объект цикла'});
          return;
        }

        const action = payload.action || 'create';
        if(action === 'delete'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          if(!id){
            sendJson(res, 400, {error:'Не указан цикл для удаления'});
            return;
          }
          queueCycleMutation(cycles=>{
            const index = cycles.findIndex((cycle,position)=>getCycleId(cycle,position) === id);
            if(index < 0){
              const error = new Error('Cycle not found');
              error.code = 'CYCLE_NOT_FOUND';
              throw error;
            }
            return cycles.filter((_,position)=>position !== index);
          },'Delete cycle from admin panel').then(cycles=>{
            sendJson(res, 200, {cycles});
          }).catch(error=>sendCycleMutationError(res,error));
          return;
        }

        if(action !== 'create' && action !== 'update'){
          sendJson(res, 400, {error:'Неизвестное действие с циклом'});
          return;
        }

        const input = payload.cycle;
        if(!input || typeof input !== 'object' || Array.isArray(input)){
          sendJson(res, 400, {error:'Не указаны данные цикла'});
          return;
        }
        const id = typeof payload.id === 'string' ? payload.id : '';
        if(action === 'update' && !id){
          sendJson(res, 400, {error:'Не указан цикл для изменения'});
          return;
        }

        let existingPoemIds;
        try{
          const currentPoems = await readPoemsFromGitHub();
          existingPoemIds = new Set(currentPoems.poems.map((poem,index)=>getPoemId(poem,index)));
        }catch(error){
          sendGitHubError(res,error,'read');
          return;
        }

        const validation = validateCycle(input,existingPoemIds);
        if(validation.error){
          sendJson(res, 400, {error:validation.error});
          return;
        }

        if(action === 'create'){
          const newCycle = {...validation.cycle,id:crypto.randomUUID()};
          queueCycleMutation(cycles=>[...cycles,newCycle],'Create cycle from admin panel').then(cycles=>{
            sendJson(res, 201, {cycles});
          }).catch(error=>sendCycleMutationError(res,error));
          return;
        }

        queueCycleMutation(cycles=>{
          const index = cycles.findIndex((cycle,position)=>getCycleId(cycle,position) === id);
          if(index < 0){
            const error = new Error('Cycle not found');
            error.code = 'CYCLE_NOT_FOUND';
            throw error;
          }
          const updated = cycles.slice();
          updated[index] = {...updated[index],...validation.cycle,...preserveOmittedImagePresentation(updated[index],input),id:getCycleId(updated[index],index)};
          return updated;
        },'Edit cycle from admin panel').then(cycles=>{
          sendJson(res, 200, {cycles});
        }).catch(error=>sendCycleMutationError(res,error));
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res,status,{error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/prose' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res,401,{error:'Требуется вход'});
        return;
      }

      readProseFromGitHub().then(({prose})=>{
        sendJson(res,200,{prose});
      }).catch(error=>sendProseGitHubError(res,error,'read'));
    }).catch(()=>sendJson(res,401,{error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/prose' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res,403,{error:'Запрос отклонён'});
      return;
    }

    getSession(req).then(session=>{
      if(!session){
        sendJson(res,401,{error:'Требуется вход'});
        return;
      }

      readRequestBody(req).then(body=>{
        let payload;
        try{
          payload = JSON.parse(body);
        }catch{
          sendJson(res,400,{error:'Некорректный JSON'});
          return;
        }

        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res,400,{error:'Ожидался объект произведения'});
          return;
        }

        const action = payload.action || 'create';
        if(action === 'create'){
          const input = payload.prose && typeof payload.prose === 'object' && !Array.isArray(payload.prose) ? payload.prose : payload;
          const validation = validateProse(input);
          if(validation.error){
            sendJson(res,400,{error:validation.error});
            return;
          }
          const newEntry = {...validation.prose,id:crypto.randomUUID()};
          queueProseMutation(prose=>[...prose,newEntry],'Create prose from admin panel').then(prose=>{
            sendJson(res,201,{prose});
          }).catch(error=>sendProseMutationError(res,error));
          return;
        }

        if(action === 'update'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          const input = payload.prose;
          if(!id || !input || typeof input !== 'object' || Array.isArray(input)){
            sendJson(res,400,{error:'Не указано произведение для изменения'});
            return;
          }
          const validation = validateProse(input);
          if(validation.error){
            sendJson(res,400,{error:validation.error});
            return;
          }
          queueProseMutation(prose=>{
            const index = prose.findIndex((entry,position)=>getProseId(entry,position) === id);
            if(index < 0){
              const error = new Error('Prose entry not found');
              error.code = 'PROSE_NOT_FOUND';
              throw error;
            }
            const updated = prose.slice();
            updated[index] = {...updated[index],...validation.prose,...preserveOmittedImagePresentation(updated[index],input),id:getProseId(updated[index],index)};
            return updated;
          },'Edit prose from admin panel').then(prose=>{
            sendJson(res,200,{prose});
          }).catch(error=>sendProseMutationError(res,error));
          return;
        }

        if(action === 'delete'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          if(!id){
            sendJson(res,400,{error:'Не указано произведение для удаления'});
            return;
          }
          queueProseMutation(prose=>{
            const index = prose.findIndex((entry,position)=>getProseId(entry,position) === id);
            if(index < 0){
              const error = new Error('Prose entry not found');
              error.code = 'PROSE_NOT_FOUND';
              throw error;
            }
            return prose.filter((_,position)=>position !== index);
          },'Delete prose from admin panel').then(prose=>{
            sendJson(res,200,{prose});
          }).catch(error=>sendProseMutationError(res,error));
          return;
        }

        sendJson(res,400,{error:'Неизвестное действие с произведением'});
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res,status,{error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res,401,{error:'Требуется вход'}));
    return;
  }

  const publicImageRecordMatch = req.url.match(/^\/api\/public-image\/(poem|prose|cycle)\/([^/?#]+)$/);
  if(publicImageRecordMatch && req.method === 'GET'){
    let recordId;
    try{recordId = decodeURIComponent(publicImageRecordMatch[2]);}catch{sendJson(res,400,{error:'Некорректный ID записи'});return;}
    if(!recordId || Buffer.byteLength(recordId,'utf8') > 300){sendJson(res,400,{error:'Некорректный ID записи'});return;}
    getPublishedRecordImage(publicImageRecordMatch[1],recordId).then(async result=>{
      if(!result){sendJson(res,404,{error:'Опубликованное изображение не найдено'});return;}
      await sendPublicImage(res,result.info,result.settings);
    }).catch(error=>{
      if(error.code === 'GITHUB_TOKEN_MISSING') sendJson(res,503,{error:'Хранилище изображений не настроено'});
      else{
        if(error.status) console.error(`Public image lookup failed with status ${error.status}`);
        else console.error('Public image lookup failed');
        sendJson(res,502,{error:'Не удалось загрузить изображение'});
      }
    });
    return;
  }

  const managedImageMatch = req.url.match(/^\/images\/(poems|prose|cycles)\/([a-f0-9]{64})\.(jpe?g|png|webp)$/i);
  if(managedImageMatch && req.method === 'GET'){
    getSession(req).then(async session=>{
      try{
        const info = getManagedImageInfo(req.url,managedImageMatch[1]);
        if(!info){sendJson(res,404,{error:'Изображение не найдено'});return;}
        let watermarkSettings = null;
        if(!session){
          let references;
          try{references = await getPublishedImageReferences(info.category,req.url);}catch(error){
            if(error.code === 'GITHUB_TOKEN_MISSING') sendJson(res,503,{error:'Хранилище изображений не настроено'});
            else sendJson(res,502,{error:'Не удалось проверить доступ к изображению'});
            return;
          }
          if(!references.length){sendJson(res,404,{error:'Изображение не найдено'});return;}
          watermarkSettings = references[0].settings;
          if(references.some(reference=>JSON.stringify(reference.settings) !== JSON.stringify(watermarkSettings))){
            sendJson(res,409,{error:'У изображения несколько вариантов watermark. Используйте контекстный маршрут записи.'});
            return;
          }
        }
        const imageFile = info && await readGitHubImage(info.filePath);
        if(!imageFile){
          sendJson(res,404,{error:'Изображение не найдено'});
          return;
        }
        const publicImage = session ? {bytes:imageFile.bytes,contentType:info.extension === 'jpg' || info.extension === 'jpeg' ? 'image/jpeg' : `image/${info.extension}`} : renderPublicWatermarkedImage(imageFile.bytes,info.extension,watermarkSettings);
        res.writeHead(200,{
          'Content-Type':publicImage.contentType,
          'Content-Length':publicImage.bytes.length,
          'Cache-Control':session ? 'private, no-store' : 'public, max-age=300',
          'Content-Disposition':'inline',
          'Referrer-Policy':'no-referrer',
          'X-Content-Type-Options':'nosniff'
        });
        res.end(publicImage.bytes);
      }catch(error){
        if(error.code === 'GITHUB_TOKEN_MISSING') sendJson(res,503,{error:'Хранилище изображений не настроено'});
        else{
          if(error.status) console.error(`GitHub image read failed with status ${error.status}`);
          else console.error('GitHub image read failed');
          sendJson(res,502,{error:'Не удалось загрузить изображение'});
        }
      }
    }).catch(()=>sendJson(res,401,{error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/images/upload' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res,403,{error:'Запрос отклонён'});
      return;
    }
    getSession(req).then(session=>{
      if(!session){
        sendJson(res,401,{error:'Требуется вход'});
        return;
      }
      const uploadBodyLimit = Math.ceil(MAX_IMAGE_SIZE_BYTES / 3) * 4 + 64 * 1024;
      readRequestBody(req,uploadBodyLimit).then(body=>{
        let payload;
        try{payload = JSON.parse(body);}catch{
          sendJson(res,400,{error:'Некорректный JSON'});
          return;
        }
        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res,400,{error:'Ожидались данные изображения'});
          return;
        }
        queueImageMutation(()=>uploadImageToGitHub(payload.category,payload.fileName,payload.contentType,payload.contentBase64)).then(result=>{
          sendJson(res,201,result);
        }).catch(error=>sendImageMutationError(res,error));
      }).catch(error=>{
        if(!res.headersSent){
          const tooLarge = error.message === 'Request body is too large';
          sendJson(res,tooLarge ? 413 : 400,{error:tooLarge ? 'Размер запроса превышает допустимые 10 MiB' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res,401,{error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/images/delete' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res,403,{error:'Запрос отклонён'});
      return;
    }
    getSession(req).then(session=>{
      if(!session){
        sendJson(res,401,{error:'Требуется вход'});
        return;
      }
      readRequestBody(req).then(body=>{
        let payload;
        try{payload = JSON.parse(body);}catch{
          sendJson(res,400,{error:'Некорректный JSON'});
          return;
        }
        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res,400,{error:'Ожидались данные изображения'});
          return;
        }
        queueImageMutation(()=>deleteImageFromGitHub(payload.category,payload.image)).then(result=>{
          sendJson(res,200,result);
        }).catch(error=>sendImageMutationError(res,error));
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res,status,{error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res,401,{error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/test'){
    res.writeHead(200,{
      'Content-Type':'application/json; charset=utf-8'
    });

    res.end(JSON.stringify({
      ok:true,
      message:'Node.js работает'
    }));

    return;
  }

  if(req.url === '/mascot.png' && req.method === 'GET'){
    fs.readFile(path.join(__dirname, 'mascot.png'), (error, image)=>{
      if(error){
        res.writeHead(404, {'Content-Type':'text/plain; charset=utf-8'});
        res.end('Not found');
        return;
      }

      res.writeHead(200, {
        'Content-Type':'image/png',
        'Content-Length':image.length,
        'Cache-Control':'public, max-age=86400',
        'X-Content-Type-Options':'nosniff'
      });
      res.end(image);
    });
    return;
  }

  if(req.url === '/' || req.url === '/index.html'){
    res.writeHead(200,{
      'Content-Type':'text/html; charset=utf-8'
    });

    res.end(html);
    return;
  }

  res.writeHead(404,{
    'Content-Type':'text/plain; charset=utf-8'
  });

  res.end('Not found');
});

const port = process.env.PORT || 3000;

initializeAdminPasswordVerifier().then(()=>{
  server.listen(port,'0.0.0.0',()=>{
    console.log('Server started on port ' + port);
  });
}).catch(()=>{
  console.error('Failed to initialize password verifier');
  process.exitCode = 1;
});
