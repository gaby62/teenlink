const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const PORT_HTTPS = 3443;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PFX_PATH = path.join(__dirname, 'cert.pfx');
const PFX_PASSWORD = 'password123';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// === SIMPLE JSON DATABASE ===
function readDB(name) {
  const file = path.join(DATA_DIR, name + '.json');
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function writeDB(name, data) {
  fs.writeFileSync(path.join(DATA_DIR, name + '.json'), JSON.stringify(data, null, 2));
}
function genId() { return crypto.randomBytes(12).toString('hex'); }
function hashPw(pw) { return crypto.scryptSync(pw, 'salt_rencontre_ados_2024', 64).toString('hex'); }
function verifyPw(pw, hash) { return crypto.scryptSync(pw, 'salt_rencontre_ados_2024', 64).toString('hex') === hash; }
function addXP(userId, amount) {
  const users = readDB('users');
  const idx = users.findIndex(u => u._id === userId);
  if (idx === -1) return;
  if (!users[idx].xp) users[idx].xp = 0;
  users[idx].xp += amount;
  users[idx].level = Math.floor(Math.sqrt(users[idx].xp / 50)) + 1;
  writeDB('users', users);
}
function canReport(userId) {
  const reports = readDB('reports');
  const last = reports.filter(r => r.reporter === userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
  if (!last) return true;
  return (Date.now() - new Date(last.createdAt).getTime()) > 3600000;
}
function createToken(userId) { return Buffer.from(userId + ':' + Date.now()).toString('base64'); }
function verifyToken(token) {
  try { return Buffer.from(token, 'base64').toString('utf8').split(':')[0]; } catch { return null; }
}
function auth(req) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return null;
  return verifyToken(h.slice(7));
}
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 10e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}
function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}
function serveStatic(req, res) {
  let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
  if (!fs.existsSync(filePath)) filePath = path.join(PUBLIC_DIR, 'index.html');
  const ext = path.extname(filePath);
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml' };
  res.writeHead(200, { 'Content-Type': types[ext] || 'text/html' });
  res.end(fs.readFileSync(filePath));
}

async function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query = parsed.query;

  if (!pathname.startsWith('/api/')) return serveStatic(req, res);

  try {
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      if (users.find(u => u.email === d.email)) return json(res, { message: 'Email déjà utilisé' }, 400);
      if (!d.email || !d.password || d.password.length < 6) return json(res, { message: 'Email et mot de passe (min 6 car.) requis' }, 400);
      if (!d.age || d.age < 13 || d.age > 18) return json(res, { message: 'Âge 13-18 ans' }, 400);
      if (!d.sex || !d.gender) return json(res, { message: 'Sexe et genre requis' }, 400);
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const ipKey = ip.replace(/::ffff:/, '').split(',')[0].trim();
      if (users.filter(u => u.registeredIP === ipKey).length >= 2) return json(res, { message: 'Limite de 2 comptes par réseau atteinte' }, 400);
      const user = { _id: genId(), email: d.email, password: hashPw(d.password), age: +d.age, sex: d.sex, gender: d.gender, hairColor: d.hairColor || '', skinColor: d.skinColor || '', eyeColor: d.eyeColor || '', height: +d.height || 0, weight: +d.weight || 0, city: d.city, phone: d.phone || '', photos: d.photos || [], interests: d.interests || [], bio: '', status: 'available', xp: 0, level: 1, blockedUsers: [], privacy: { showAge: true, showCity: true, showPhotos: true }, emailVerified: false, lastSeen: new Date().toISOString(), registeredIP: ipKey, createdAt: new Date().toISOString() };
      users.push(user); writeDB('users', users);
      const token = createToken(user._id);
      const { password, ...safe } = user;
      return json(res, { token, user: safe }, 201);
    }

    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u.email === d.email);
      if (idx === -1 || !verifyPw(d.password, users[idx].password)) return json(res, { message: 'Email ou mot de passe incorrect' }, 400);
      users[idx].lastSeen = new Date().toISOString();
      writeDB('users', users);
      const token = createToken(users[idx]._id);
      const { password, ...safe } = users[idx];
      return json(res, { token, user: safe });
    }

    // === EMAIL VERIFICATION (#10) ===
    if (pathname === '/api/auth/send-verification' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const user = users.find(u => u.email === d.email);
      if (!user) return json(res, { message: 'Si cet email existe, un code a été envoyé.' });
      const code = Math.random().toString(36).substring(2, 8).toUpperCase();
      const tokens = readDB('tokens');
      tokens.push({ _id: genId(), userId: user._id, code, type: 'verification', expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() });
      writeDB('tokens', tokens);
      console.log(`[VERIFICATION] Code pour ${d.email}: ${code}`);
      return json(res, { message: 'Code envoyé (voir la console du serveur)', code });
    }

    if (pathname === '/api/auth/verify-email' && req.method === 'POST') {
      const d = await parseBody(req);
      const tokens = readDB('tokens');
      const token = tokens.find(t => t.code === d.code && t.type === 'verification' && new Date(t.expiresAt) > new Date());
      if (!token) return json(res, { message: 'Code invalide ou expiré' }, 400);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === token.userId);
      if (idx !== -1) { users[idx].emailVerified = true; writeDB('users', users); }
      writeDB('tokens', tokens.filter(t => t._id !== token._id));
      return json(res, { message: 'Email vérifié !' });
    }

    // === HEARTBEAT (online status) (#5) ===
    if (pathname === '/api/heartbeat' && req.method === 'POST') {
      const hbUserId = auth(req);
      if (hbUserId) {
        const users = readDB('users');
        const idx = users.findIndex(u => u._id === hbUserId);
        if (idx !== -1) { users[idx].lastSeen = new Date().toISOString(); writeDB('users', users); }
      }
      return json(res, { ok: true });
    }

    const userId = auth(req);
    if (!userId) return json(res, { message: 'Non autorisé' }, 401);

    if (pathname === '/api/users/me' && req.method === 'GET') {
      const users = readDB('users');
      const user = users.find(u => u._id === userId);
      if (!user) return json(res, { message: 'Non trouvé' }, 404);
      const { password, ...safe } = user;
      return json(res, safe);
    }

    if (pathname === '/api/users/me' && req.method === 'PUT') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      ['phone', 'hairColor', 'skinColor', 'eyeColor', 'height', 'weight', 'city', 'photos', 'interests', 'bio', 'privacy', 'blockedUsers'].forEach(f => { if (d[f] !== undefined) users[idx][f] = d[f]; });
      writeDB('users', users);
      const { password, ...safe } = users[idx];
      return json(res, safe);
    }

    // === STATUS (MOOD) ===
    if (pathname === '/api/users/status' && req.method === 'PUT') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      const validStatuses = ['available', 'busy', 'studying', 'away', 'invisible'];
      if (!validStatuses.includes(d.status)) return json(res, { message: 'Statut invalide' }, 400);
      users[idx].status = d.status;
      writeDB('users', users);
      return json(res, { message: 'Statut mis à jour', status: d.status });
    }

    // === BLOCKED LIST ===
    if (pathname === '/api/users/blocked' && req.method === 'GET') {
      const users = readDB('users');
      const me = users.find(u => u._id === userId);
      if (!me) return json(res, { message: 'Non trouvé' }, 404);
      const blocked = (me.blockedUsers || []).map(id => {
        const u = users.find(u => u._id === id);
        if (!u) return null;
        const { password, ...s } = u;
        return s;
      }).filter(Boolean);
      return json(res, blocked);
    }

    if (pathname === '/api/users/block' && req.method === 'POST') {
      const d = await parseBody(req);
      if (d.userId === userId) return json(res, { message: 'Impossible de se bloquer' }, 400);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      if (!users[idx].blockedUsers) users[idx].blockedUsers = [];
      if (!users[idx].blockedUsers.includes(d.userId)) {
        users[idx].blockedUsers.push(d.userId);
        writeDB('users', users);
      }
      return json(res, { message: 'Bloqué' });
    }

    if (pathname === '/api/users/unblock' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      users[idx].blockedUsers = (users[idx].blockedUsers || []).filter(id => id !== d.userId);
      writeDB('users', users);
      return json(res, { message: 'Débloqué' });
    }

    // === LIKES RECEIVED ===
    if (pathname === '/api/likes/received' && req.method === 'GET') {
      const likes = readDB('likes');
      const users = readDB('users');
      const received = likes.filter(l => l.to === userId);
      const result = received.map(l => {
        const u = users.find(u => u._id === l.from);
        if (!u) return null;
        const { password, ...s } = u;
        return { ...s, likedAt: l.createdAt };
      }).filter(Boolean);
      return json(res, result);
    }

    // === COMPATIBILITY SCORE ===
    if (pathname === '/api/users/compatibility' && req.method === 'GET') {
      const targetId = query.userId;
      if (!targetId) return json(res, { message: 'userId requis' }, 400);
      const users = readDB('users');
      const me = users.find(u => u._id === userId);
      const them = users.find(u => u._id === targetId);
      if (!me || !them) return json(res, { message: 'Non trouvé' }, 404);
      let score = 0, total = 0;
      if (me.city && them.city) { total += 20; if (me.city.toLowerCase() === them.city.toLowerCase()) score += 20; }
      if (me.age && them.age) { total += 15; const diff = Math.abs(me.age - them.age); if (diff===0) score+=15; else if (diff===1) score+=10; else if (diff===2) score+=5; }
      if (me.interests && them.interests && me.interests.length > 0 && them.interests.length > 0) { const common = me.interests.filter(i => them.interests.includes(i)); total += 50; score += Math.round((common.length / Math.min(me.interests.length, them.interests.length)) * 50); }
      if (me.sex && them.gender) { total += 15; if ((me.sex==='M'&&them.gender==='femme')||(me.sex==='F'&&them.gender==='homme')||them.gender==='autre') score += 15; }
      const pct = total > 0 ? Math.round((score / total) * 100) : 0;
      return json(res, { score: pct });
    }

    // === MUTUAL FRIENDS ===
    if (pathname === '/api/users/mutual-friends' && req.method === 'GET') {
      const targetId = query.userId;
      if (!targetId) return json(res, { message: 'userId requis' }, 400);
      const friends = readDB('friends');
      const users = readDB('users');
      const myFriends = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId)).map(f => f.sender === userId ? f.receiver : f.sender);
      const theirFriends = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).map(f => f.sender === targetId ? f.receiver : f.sender);
      const mutualIds = myFriends.filter(id => theirFriends.includes(id));
      const mutual = mutualIds.map(id => { const u = users.find(u => u._id === id); if (!u) return null; const { password, ...s } = u; return s; }).filter(Boolean);
      return json(res, mutual);
    }

    // === STATS ===
    if (pathname === '/api/users/stats' && req.method === 'GET') {
      const targetId = query.userId || userId;
      const users = readDB('users');
      const friends = readDB('friends');
      const likes = readDB('likes');
      const messages = readDB('messages');
      const user = users.find(u => u._id === targetId);
      if (!user) return json(res, { message: 'Non trouvé' }, 404);
      const friendCount = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).length;
      const likeCount = likes.filter(l => l.to === targetId).length;
      const likeGiven = likes.filter(l => l.from === targetId).length;
      const msgCount = messages.filter(m => m.sender === targetId).length;
      const notifs = readDB('notifications');
      const unreadNotifs = notifs.filter(n => n.user === targetId && !n.read).length;
      const daysSinceCreation = Math.floor((Date.now() - new Date(user.createdAt).getTime()) / 86400000);
      return json(res, { friends: friendCount, likesReceived: likeCount, likesGiven: likeGiven, messagesSent: msgCount, unreadNotifications: unreadNotifs, memberSince: user.createdAt, daysActive: daysSinceCreation });
    }

    if (pathname === '/api/users/search' && req.method === 'GET') {
      const users = readDB('users');
      let results = users.filter(u => u._id !== userId);
      if (query.city) results = results.filter(u => u.city && u.city.toLowerCase().includes(query.city.toLowerCase()));
      if (query.ageMin) results = results.filter(u => u.age >= +query.ageMin);
      if (query.ageMax) results = results.filter(u => u.age <= +query.ageMax);
      if (query.interests) { const ints = query.interests.split(','); results = results.filter(u => u.interests && ints.some(i => u.interests.includes(i))); }
      return json(res, results.map(u => { const { password, ...s } = u; return s; }).slice(0, 50));
    }

    // === XP & LEVELS ===
    if (pathname === '/api/users/xp' && req.method === 'GET') {
      const targetId = query.userId || userId;
      const users = readDB('users');
      const u = users.find(u => u._id === targetId);
      if (!u) return json(res, { xp: 0, level: 1, nextLevel: 50 });
      const xp = u.xp || 0;
      const level = u.level || 1;
      const nextLevel = Math.pow(level, 2) * 50;
      return json(res, { xp, level, nextLevel });
    }

    // === EXPLORER ===
    if (pathname === '/api/users/explore' && req.method === 'GET') {
      const users = readDB('users');
      const friends = readDB('friends');
      const blocked = users.find(u => u._id === userId)?.blockedUsers || [];
      const friendIds = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId)).map(f => f.sender === userId ? f.receiver : f.sender);
      const exclude = [userId, ...friendIds, ...blocked];
      let candidates = users.filter(u => !exclude.includes(u._id));
      const city = query.city;
      const interest = query.interest;
      const ageMin = query.ageMin ? +query.ageMin : 0;
      const ageMax = query.ageMax ? +query.ageMax : 20;
      if (city) candidates = candidates.filter(u => u.city && u.city.toLowerCase() === city.toLowerCase());
      if (interest) candidates = candidates.filter(u => u.interests && u.interests.includes(interest));
      candidates = candidates.filter(u => u.age >= ageMin && u.age <= ageMax);
      candidates.sort(() => Math.random() - 0.5);
      return json(res, candidates.slice(0, 10).map(u => { const { password, ...s } = u; return s; }));
    }

    // === COMPATIBILITY SCORE ===
    if (pathname === '/api/users/compatibility' && req.method === 'GET') {
      const targetId = query.userId;
      if (!targetId) return json(res, { message: 'userId requis' }, 400);
      const users = readDB('users');
      const me = users.find(u => u._id === userId);
      const them = users.find(u => u._id === targetId);
      if (!me || !them) return json(res, { message: 'Non trouvé' }, 404);
      let score = 0, total = 0;
      if (me.city && them.city) { total += 20; if (me.city.toLowerCase() === them.city.toLowerCase()) score += 20; }
      if (me.age && them.age) { total += 15; const diff = Math.abs(me.age - them.age); if (diff===0) score+=15; else if (diff===1) score+=10; else if (diff===2) score+=5; }
      if (me.interests && them.interests && me.interests.length > 0 && them.interests.length > 0) { const common = me.interests.filter(i => them.interests.includes(i)); total += 50; score += Math.round((common.length / Math.min(me.interests.length, them.interests.length)) * 50); }
      if (me.sex && them.gender) { total += 15; if ((me.sex==='M'&&them.gender==='femme')||(me.sex==='F'&&them.gender==='homme')||them.gender==='autre') score += 15; }
      const pct = total > 0 ? Math.round((score / total) * 100) : 0;
      return json(res, { score: pct });
    }

    // === MUTUAL FRIENDS ===
    if (pathname === '/api/users/mutual-friends' && req.method === 'GET') {
      const targetId = query.userId;
      if (!targetId) return json(res, { message: 'userId requis' }, 400);
      const friends = readDB('friends');
      const users = readDB('users');
      const myFriends = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId)).map(f => f.sender === userId ? f.receiver : f.sender);
      const theirFriends = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).map(f => f.sender === targetId ? f.receiver : f.sender);
      const mutualIds = myFriends.filter(id => theirFriends.includes(id));
      const mutual = mutualIds.map(id => { const u = users.find(u => u._id === id); if (!u) return null; const { password, ...s } = u; return s; }).filter(Boolean);
      return json(res, mutual);
    }

    // === STATS ===
    if (pathname === '/api/users/stats' && req.method === 'GET') {
      const targetId = query.userId || userId;
      const users = readDB('users');
      const friends = readDB('friends');
      const likes = readDB('likes');
      const messages = readDB('messages');
      const user = users.find(u => u._id === targetId);
      if (!user) return json(res, { message: 'Non trouvé' }, 404);
      const friendCount = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).length;
      const likeCount = likes.filter(l => l.to === targetId).length;
      const likeGiven = likes.filter(l => l.from === targetId).length;
      const msgCount = messages.filter(m => m.sender === targetId).length;
      const notifs = readDB('notifications');
      const unreadNotifs = notifs.filter(n => n.user === targetId && !n.read).length;
      const daysSinceCreation = Math.floor((Date.now() - new Date(user.createdAt).getTime()) / 86400000);
      return json(res, { friends: friendCount, likesReceived: likeCount, likesGiven: likeGiven, messagesSent: msgCount, unreadNotifications: unreadNotifs, memberSince: user.createdAt, daysActive: daysSinceCreation });
    }

    const userIdMatch = pathname.match(/^\/api\/users\/([^/]+)$/);
    if (userIdMatch && req.method === 'GET') {
      const users = readDB('users');
      const user = users.find(u => u._id === userIdMatch[1]);
      if (!user) return json(res, { message: 'Non trouvé' }, 404);
      const { password, ...safe } = user;
      return json(res, safe);
    }

    if (pathname === '/api/friends/request' && req.method === 'POST') {
      const d = await parseBody(req);
      if (d.receiverId === userId) return json(res, { message: 'Vous ne pouvez pas vous ajouter' }, 400);
      const friends = readDB('friends');
      const existing = friends.find(f => (f.sender === userId && f.receiver === d.receiverId) || (f.sender === d.receiverId && f.receiver === userId));
      if (existing) return json(res, { message: existing.status === 'accepted' ? 'Déjà amis' : 'Demande en cours' }, 400);
      const fr = { _id: genId(), sender: userId, receiver: d.receiverId, status: 'pending', createdAt: new Date().toISOString() };
      friends.push(fr); writeDB('friends', friends);
      const notifs = readDB('notifications');
      notifs.push({ _id: genId(), user: d.receiverId, type: 'friend_request', from: userId, message: 'Nouvelle demande d\'ami', read: false, createdAt: new Date().toISOString() });
      writeDB('notifications', notifs);
      return json(res, { message: 'Demande envoyée' }, 201);
    }

    if (pathname.match(/^\/api\/friends\/accept\//) && req.method === 'PUT') {
      const id = pathname.split('/').pop();
      const friends = readDB('friends');
      const fr = friends.find(f => f._id === id);
      if (!fr || fr.receiver !== userId) return json(res, { message: 'Non autorisé' }, 403);
      fr.status = 'accepted'; writeDB('friends', friends);
      addXP(userId, 10);
      addXP(fr.sender, 10);
      const notifs = readDB('notifications');
      notifs.push({ _id: genId(), user: fr.sender, type: 'friend_accepted', from: userId, message: 'Demande acceptée !', read: false, createdAt: new Date().toISOString() });
      writeDB('notifications', notifs);
      return json(res, { message: 'Accepté' });
    }

    if (pathname.match(/^\/api\/friends\/reject\//) && req.method === 'PUT') {
      const id = pathname.split('/').pop();
      const friends = readDB('friends');
      const fr = friends.find(f => f._id === id);
      if (!fr || fr.receiver !== userId) return json(res, { message: 'Non autorisé' }, 403);
      fr.status = 'rejected'; writeDB('friends', friends);
      return json(res, { message: 'Refusé' });
    }

    if (pathname === '/api/friends/list' && req.method === 'GET') {
      const friends = readDB('friends');
      const users = readDB('users');
      const accepted = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId));
      return json(res, accepted.map(f => { const u = users.find(u => u._id === (f.sender === userId ? f.receiver : f.sender)); if (!u) return null; const { password, ...s } = u; return s; }).filter(Boolean));
    }

    if (pathname === '/api/friends/pending' && req.method === 'GET') {
      const friends = readDB('friends');
      const users = readDB('users');
      return json(res, friends.filter(f => f.status === 'pending' && f.receiver === userId).map(f => { const u = users.find(u => u._id === f.sender); if (!u) return null; const { password, ...s } = u; return { _id: f._id, sender: s, createdAt: f.createdAt }; }).filter(Boolean));
    }

    if (pathname.match(/^\/api\/friends\/status\//) && req.method === 'GET') {
      const targetId = pathname.split('/').pop();
      const friends = readDB('friends');
      const fr = friends.find(f => (f.sender === userId && f.receiver === targetId) || (f.sender === targetId && f.receiver === userId));
      return json(res, fr ? { status: fr.status, requestId: fr._id } : { status: 'none' });
    }

    if (pathname === '/api/messages' && req.method === 'POST') {
      const d = await parseBody(req);
      const friends = readDB('friends');
      if (!friends.find(f => f.status === 'accepted' && ((f.sender === userId && f.receiver === d.receiverId) || (f.sender === d.receiverId && f.receiver === userId))))
        return json(res, { message: 'Vous devez être amis' }, 403);
      const messages = readDB('messages');
      const msg = { _id: genId(), sender: userId, receiver: d.receiverId, content: d.content, read: false, createdAt: new Date().toISOString() };
      messages.push(msg); writeDB('messages', messages);
      addXP(userId, 5);
      const notifs = readDB('notifications');
      notifs.push({ _id: genId(), user: d.receiverId, type: 'new_message', from: userId, message: 'Nouveau message', read: false, createdAt: new Date().toISOString() });
      writeDB('notifications', notifs);
      const users = readDB('users');
      const s = users.find(u => u._id === userId); const r = users.find(u => u._id === d.receiverId);
      return json(res, { ...msg, sender: s ? (() => { const { password, ...p } = s; return p; })() : null, receiver: r ? (() => { const { password, ...p } = r; return p; })() : null }, 201);
    }

    if (pathname === '/api/messages/conversations' && req.method === 'GET') {
      const friends = readDB('friends');
      const messages = readDB('messages');
      const users = readDB('users');
      const accepted = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId));
      const convos = [];
      for (const f of accepted) {
        const fid = f.sender === userId ? f.receiver : f.sender;
        const msgs = messages.filter(m => (m.sender === userId && m.receiver === fid) || (m.sender === fid && m.receiver === userId)).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
        const user = users.find(u => u._id === fid);
        if (user) { const { password, ...s } = user; convos.push({ user: s, lastMessage: msgs[msgs.length - 1] || null, unread: messages.filter(m => m.sender === fid && m.receiver === userId && !m.read).length }); }
      }
      convos.sort((a, b) => (b.lastMessage?.createdAt || '').localeCompare(a.lastMessage?.createdAt || ''));
      return json(res, convos);
    }

    if (pathname.match(/^\/api\/messages\/[^/]+$/) && req.method === 'GET' && !pathname.includes('conversations')) {
      const otherId = pathname.split('/').pop();
      const messages = readDB('messages');
      const users = readDB('users');
      const msgs = messages.filter(m => (m.sender === userId && m.receiver === otherId) || (m.sender === otherId && m.receiver === userId)).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      msgs.forEach(m => { if (m.sender === otherId && m.receiver === userId) m.read = true; });
      writeDB('messages', messages);
      return json(res, msgs.map(m => {
        const s = users.find(u => u._id === m.sender); const r = users.find(u => u._id === m.receiver);
        return { ...m, sender: s ? (() => { const { password, ...p } = s; return p; })() : m.sender, receiver: r ? (() => { const { password, ...p } = r; return p; })() : m.receiver };
      }));
    }

    if (pathname === '/api/notifications' && req.method === 'GET') {
      const notifs = readDB('notifications');
      const users = readDB('users');
      return json(res, notifs.filter(n => n.user === userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50).map(n => {
        const from = users.find(u => u._id === n.from);
        return { ...n, from: from ? (() => { const { password, ...s } = from; return s; })() : null };
      }));
    }

    if (pathname === '/api/notifications/unread-count' && req.method === 'GET') {
      return json(res, { count: readDB('notifications').filter(n => n.user === userId && !n.read).length });
    }

    if (pathname === '/api/notifications/read-all' && req.method === 'PUT') {
      const notifs = readDB('notifications');
      notifs.forEach(n => { if (n.user === userId) n.read = true; });
      writeDB('notifications', notifs);
      return json(res, { message: 'OK' });
    }

    // === REPORTS (#1) ===
    if (pathname === '/api/reports' && req.method === 'POST') {
      if (!canReport(userId)) return json(res, { message: 'Attends 1h entre chaque signalement' }, 429);
      const d = await parseBody(req);
      const reports = readDB('reports');
      const report = { _id: genId(), reporter: userId, reportedUser: d.reportedUser, reason: d.reason, details: d.details || '', createdAt: new Date().toISOString() };
      reports.push(report); writeDB('reports', reports);
      return json(res, { message: 'Signalement envoyé' }, 201);
    }

    // === BLOCK (#2) ===
    if (pathname === '/api/users/block' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      if (!users[idx].blockedUsers) users[idx].blockedUsers = [];
      if (!users[idx].blockedUsers.includes(d.userId)) {
        users[idx].blockedUsers.push(d.userId);
        writeDB('users', users);
      }
      return json(res, { message: 'Utilisateur bloqué' });
    }

    if (pathname === '/api/users/unblock' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      users[idx].blockedUsers = (users[idx].blockedUsers || []).filter(id => id !== d.userId);
      writeDB('users', users);
      return json(res, { message: 'Utilisateur débloqué' });
    }

    if (pathname === '/api/users/blocked' && req.method === 'GET') {
      const users = readDB('users');
      const me = users.find(u => u._id === userId);
      const blockedIds = me?.blockedUsers || [];
      const blocked = users.filter(u => blockedIds.includes(u._id)).map(u => { const { password, ...s } = u; return s; });
      return json(res, blocked);
    }

    // === PASSWORD RESET (#5) ===
    if (pathname === '/api/auth/forgot-password' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const user = users.find(u => u.email === d.email);
      if (!user) return json(res, { message: 'Si cet email existe, un code a été envoyé.' });
      const code = Math.random().toString(36).substring(2, 8).toUpperCase();
      const tokens = readDB('tokens');
      tokens.push({ _id: genId(), userId: user._id, code, expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() });
      writeDB('tokens', tokens);
      console.log(`[RESET] Code pour ${d.email}: ${code}`);
      return json(res, { message: 'Code envoyé (voir la console du serveur)', code });
    }

    if (pathname === '/api/auth/reset-password' && req.method === 'POST') {
      const d = await parseBody(req);
      const tokens = readDB('tokens');
      const token = tokens.find(t => t.code === d.code && t.userId === d.userId && new Date(t.expiresAt) > new Date());
      if (!token) return json(res, { message: 'Code invalide ou expiré' }, 400);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === d.userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      users[idx].password = hashPw(d.newPassword);
      writeDB('users', users);
      writeDB('tokens', tokens.filter(t => t._id !== token._id));
      return json(res, { message: 'Mot de passe réinitialisé' });
    }

    // === CHANGE PASSWORD (#11) ===
    if (pathname === '/api/auth/change-password' && req.method === 'POST') {
      const d = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u._id === userId);
      if (idx === -1) return json(res, { message: 'Non trouvé' }, 404);
      if (!verifyPw(d.currentPassword, users[idx].password)) return json(res, { message: 'Mot de passe actuel incorrect' }, 400);
      if (!d.newPassword || d.newPassword.length < 6) return json(res, { message: 'Nouveau mot de passe min 6 car.' }, 400);
      users[idx].password = hashPw(d.newPassword);
      writeDB('users', users);
      return json(res, { message: 'Mot de passe changé' });
    }

    // === SUGGESTED FRIENDS (#8) ===
    if (pathname === '/api/users/suggested' && req.method === 'GET') {
      const users = readDB('users');
      const me = users.find(u => u._id === userId);
      const friends = readDB('friends');
      const friendIds = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId)).map(f => f.sender === userId ? f.receiver : f.sender);
      friendIds.push(userId);
      if (me.blockedUsers) friendIds.push(...me.blockedUsers);
      const candidates = users.filter(u => !friendIds.includes(u._id));
      const scored = candidates.map(u => {
        let score = 0;
        if (u.city && me.city && u.city.toLowerCase() === me.city.toLowerCase()) score += 3;
        if (me.interests && u.interests) {
          const common = me.interests.filter(i => u.interests.includes(i));
          score += common.length;
        }
        const ageDiff = Math.abs(u.age - me.age);
        score -= ageDiff * 0.5;
        return { ...u, _score: score };
      });
      scored.sort((a, b) => b._score - a._score);
      return json(res, scored.slice(0, 20).map(u => { const { password, _score, ...s } = u; return s; }));
    }

    // === LIKES (#13) ===
    if (pathname === '/api/likes' && req.method === 'POST') {
      const d = await parseBody(req);
      const likes = readDB('likes');
      const existing = likes.find(l => l.from === userId && l.to === d.userId);
      if (existing) {
        return json(res, { message: 'Déjà liké' }, 400);
      }
      likes.push({ _id: genId(), from: userId, to: d.userId, createdAt: new Date().toISOString() });
      writeDB('likes', likes);
      addXP(userId, 2);
      addXP(d.userId, 3);
      const notifs = readDB('notifications');
      notifs.push({ _id: genId(), user: d.userId, type: 'like', from: userId, message: 'Ça lui plaît !', read: false, createdAt: new Date().toISOString() });
      writeDB('notifications', notifs);
      return json(res, { message: 'Liked' }, 201);
    }

    if (pathname === '/api/likes/unlike' && req.method === 'POST') {
      const d = await parseBody(req);
      let likes = readDB('likes');
      likes = likes.filter(l => !(l.from === userId && l.to === d.userId));
      writeDB('likes', likes);
      return json(res, { message: 'Retiré' });
    }

    if (pathname === '/api/likes/check' && req.method === 'GET') {
      const targetId = query.userId;
      const likes = readDB('likes');
      const liked = likes.some(l => l.from === userId && l.to === targetId);
      const count = likes.filter(l => l.to === targetId).length;
      return json(res, { liked, count });
    }

    if (pathname === '/api/likes/mutual' && req.method === 'GET') {
      const likes = readDB('likes');
      const mutual = likes.filter(l => l.to === userId && likes.some(l2 => l2.from === userId && l2.to === l.from));
      const users = readDB('users');
      const result = mutual.map(l => {
        const u = users.find(u => u._id === l.from);
        if (!u) return null;
        const { password, ...s } = u; return s;
      }).filter(Boolean);
      return json(res, result);
    }

    // === BADGES (#18) ===
    if (pathname === '/api/badges' && req.method === 'GET') {
      const targetId = query.userId || userId;
      const users = readDB('users');
      const friends = readDB('friends');
      const likes = readDB('likes');
      const messages = readDB('messages');
      const user = users.find(u => u._id === targetId);
      if (!user) return json(res, []);
      const badges = [];
      const friendCount = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).length;
      const likeCount = likes.filter(l => l.to === targetId).length;
      const msgCount = messages.filter(m => m.sender === targetId).length;
      const daysSinceCreation = Math.floor((Date.now() - new Date(user.createdAt).getTime()) / 86400000);
      if (likeCount >= 10) badges.push({ id: 'popular', name: 'Populaire', icon: '🌟', desc: '10+ likes reçus' });
      if (likeCount >= 5) badges.push({ id: 'liked', name: 'Apprécié', icon: '❤️', desc: '5+ likes reçus' });
      if (friendCount >= 5) badges.push({ id: 'social', name: 'Social', icon: '👥', desc: '5+ amis' });
      if (friendCount >= 10) badges.push({ id: 'topfriend', name: 'Top Ami', icon: '🏆', desc: '10+ amis' });
      if (msgCount >= 50) badges.push({ id: 'active', name: 'Actif', icon: '🔥', desc: '50+ messages envoyés' });
      if (msgCount >= 100) badges.push({ id: 'chatter', name: 'Bavard', icon: '💬', desc: '100+ messages' });
      if (daysSinceCreation <= 7) badges.push({ id: 'new', name: 'Nouveau', icon: '🌱', desc: 'Inscrit depuis moins d\'une semaine' });
      if (user.emailVerified) badges.push({ id: 'verified', name: 'Vérifié', icon: '✅', desc: 'Email vérifié' });
      return json(res, badges);
    }

    // === REPUTATION (#17) ===
    if (pathname === '/api/reputation' && req.method === 'GET') {
      const targetId = query.userId || userId;
      const likes = readDB('likes');
      const friends = readDB('friends');
      const messages = readDB('messages');
      const likeCount = likes.filter(l => l.to === targetId).length;
      const friendCount = friends.filter(f => f.status === 'accepted' && (f.sender === targetId || f.receiver === targetId)).length;
      const msgCount = messages.filter(m => m.sender === targetId).length;
      const score = likeCount * 2 + friendCount * 3 + msgCount;
      return json(res, { likes: likeCount, friends: friendCount, messages: msgCount, score });
    }

    // === REACTIONS ===
    if (pathname === '/api/messages/react' && req.method === 'POST') {
      const d = await parseBody(req);
      if (!d.messageId || !d.emoji) return json(res, { message: 'messageId et emoji requis' }, 400);
      const messages = readDB('messages');
      const idx = messages.findIndex(m => m._id === d.messageId);
      if (idx === -1) return json(res, { message: 'Message non trouvé' }, 404);
      if (!messages[idx].reactions) messages[idx].reactions = {};
      if (!messages[idx].reactions[d.emoji]) messages[idx].reactions[d.emoji] = [];
      const rIdx = messages[idx].reactions[d.emoji].indexOf(userId);
      if (rIdx === -1) {
        messages[idx].reactions[d.emoji].push(userId);
      } else {
        messages[idx].reactions[d.emoji].splice(rIdx, 1);
        if (messages[idx].reactions[d.emoji].length === 0) delete messages[idx].reactions[d.emoji];
      }
      writeDB('messages', messages);
      return json(res, { reactions: messages[idx].reactions });
    }

    // === STORIES ===
    if (pathname === '/api/stories' && req.method === 'GET') {
      const stories = readDB('stories');
      const users = readDB('users');
      const now = Date.now();
      const active = stories.filter(s => (now - new Date(s.createdAt).getTime()) < 86400000);
      const friends = readDB('friends');
      const friendIds = friends.filter(f => f.status === 'accepted' && (f.sender === userId || f.receiver === userId)).map(f => f.sender === userId ? f.receiver : f.sender);
      const result = active.map(s => {
        const u = users.find(u => u._id === s.userId);
        if (!u) return null;
        const { password, ...safe } = u;
        return { ...s, user: safe, isMine: s.userId === userId, isFriend: friendIds.includes(s.userId) };
      }).filter(Boolean);
      result.sort((a, b) => (a.isMine ? -1 : 1) - (b.isMine ? -1 : 1));
      return json(res, result);
    }

    if (pathname === '/api/stories' && req.method === 'POST') {
      const d = await parseBody(req);
      if (!d.content) return json(res, { message: 'Contenu requis' }, 400);
      const stories = readDB('stories');
      stories.push({ _id: genId(), userId, content: d.content, caption: d.caption || '', reactions: {}, createdAt: new Date().toISOString() });
      writeDB('stories', stories);
      addXP(userId, 5);
      return json(res, { message: 'Story publiée' }, 201);
    }

    if (pathname.match(/^\/api\/stories\/[^/]+\/react$/) && req.method === 'POST') {
      const storyId = pathname.split('/')[3];
      const d = await parseBody(req);
      const stories = readDB('stories');
      const idx = stories.findIndex(s => s._id === storyId);
      if (idx === -1) return json(res, { message: 'Story non trouvée' }, 404);
      if (!stories[idx].reactions) stories[idx].reactions = {};
      if (!stories[idx].reactions[d.emoji]) stories[idx].reactions[d.emoji] = [];
      const rIdx = stories[idx].reactions[d.emoji].indexOf(userId);
      if (rIdx === -1) stories[idx].reactions[d.emoji].push(userId);
      else { stories[idx].reactions[d.emoji].splice(rIdx, 1); if (stories[idx].reactions[d.emoji].length === 0) delete stories[idx].reactions[d.emoji]; }
      writeDB('stories', stories);
      return json(res, { reactions: stories[idx].reactions });
    }

    if (pathname.match(/^\/api\/stories\/[^/]+$/) && req.method === 'DELETE') {
      const storyId = pathname.split('/').pop();
      let stories = readDB('stories');
      const story = stories.find(s => s._id === storyId);
      if (!story || story.userId !== userId) return json(res, { message: 'Non autorisé' }, 403);
      stories = stories.filter(s => s._id !== storyId);
      writeDB('stories', stories);
      return json(res, { message: 'Story supprimée' });
    }

    // === POLLS ===
    if (pathname === '/api/polls' && req.method === 'POST') {
      const d = await parseBody(req);
      if (!d.question || !d.options || d.options.length < 2) return json(res, { message: 'Question et 2 options min' }, 400);
      const polls = readDB('polls');
      const poll = { _id: genId(), creatorId: userId, question: d.question, options: d.options.map(o => ({ text: o, voters: [] })), createdAt: new Date().toISOString() };
      polls.push(poll); writeDB('polls', polls);
      addXP(userId, 5);
      return json(res, poll, 201);
    }

    if (pathname.match(/^\/api\/polls\/[^/]+\/vote$/) && req.method === 'POST') {
      const pollId = pathname.split('/')[3];
      const d = await parseBody(req);
      const polls = readDB('polls');
      const idx = polls.findIndex(p => p._id === pollId);
      if (idx === -1) return json(res, { message: 'Sondage non trouvé' }, 404);
      polls[idx].options.forEach(o => { o.voters = o.voters.filter(v => v !== userId); });
      const opt = polls[idx].options.find(o => o.text === d.option);
      if (opt) opt.voters.push(userId);
      writeDB('polls', polls);
      return json(res, polls[idx]);
    }

    if (pathname === '/api/polls/recent' && req.method === 'GET') {
      const polls = readDB('polls');
      const users = readDB('users');
      const recent = polls.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20).map(p => {
        const u = users.find(u => u._id === p.creatorId);
        return { ...p, creator: u ? (() => { const { password, ...s } = u; return s; })() : null };
      });
      return json(res, recent);
    }

    // === STICKERS ===
    if (pathname === '/api/stickers' && req.method === 'GET') {
      const stickers = readDB('stickers');
      return json(res, stickers);
    }

    if (pathname === '/api/stickers' && req.method === 'POST') {
      const d = await parseBody(req);
      if (!d.name || !d.image) return json(res, { message: 'Nom et image requis' }, 400);
      const stickers = readDB('stickers');
      const sticker = { _id: genId(), name: d.name, image: d.image, uploadedBy: userId, downloads: 0, createdAt: new Date().toISOString() };
      stickers.push(sticker); writeDB('stickers', stickers);
      addXP(userId, 3);
      return json(res, sticker, 201);
    }

    if (pathname.match(/^\/api\/stickers\/[^/]+\/download$/) && req.method === 'POST') {
      const stickerId = pathname.split('/')[3];
      const stickers = readDB('stickers');
      const idx = stickers.findIndex(s => s._id === stickerId);
      if (idx !== -1) { stickers[idx].downloads = (stickers[idx].downloads || 0) + 1; writeDB('stickers', stickers); }
      return json(res, { message: 'OK' });
    }

    if (pathname.match(/^\/api\/stickers\/[^/]+$/) && req.method === 'DELETE') {
      const stickerId = pathname.split('/').pop();
      let stickers = readDB('stickers');
      const s = stickers.find(s => s._id === stickerId);
      if (!s || s.uploadedBy !== userId) return json(res, { message: 'Non autorisé' }, 403);
      stickers = stickers.filter(s => s._id !== stickerId);
      writeDB('stickers', stickers);
      return json(res, { message: 'Supprimé' });
    }

    return json(res, { message: 'Route non trouvée' }, 404);
  } catch (err) {
    console.error(err);
    return json(res, { message: 'Erreur: ' + err.message }, 500);
  }
}

// === INIT STICKERS ===
const defaultStickers = [
  { _id: 's_default_1', name: 'Thumbs Up', emoji: '👍', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">👍</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_2', name: 'Heart', emoji: '❤️', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">❤️</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_3', name: 'Fire', emoji: '🔥', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🔥</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_4', name: 'Laugh', emoji: '😂', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">😂</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_5', name: 'Cool', emoji: '😎', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">😎</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_6', name: 'Sparkles', emoji: '✨', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">✨</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_7', name: 'Clap', emoji: '👏', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">👏</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_8', name: 'Wave', emoji: '👋', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">👋</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_9', name: 'Think', emoji: '🤔', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🤔</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_10', name: 'Party', emoji: '🎉', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🎉</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_11', name: 'Strong', emoji: '💪', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">💪</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
  { _id: 's_default_12', name: 'Star', emoji: '⭐', image: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">⭐</text></svg>', uploadedBy: 'system', downloads: 0, createdAt: new Date().toISOString() },
];
if (!fs.existsSync(path.join(DATA_DIR, 'stickers.json'))) writeDB('stickers', defaultStickers);

// === START SERVERS ===
// HTTP server (redirects to HTTPS in production, works locally)
const httpServer = http.createServer(handleRequest);
httpServer.listen(PORT, () => {
  console.log('TeenLink actif sur le port ' + PORT);
});

// HTTPS server (local only)
if (!process.env.PORT && fs.existsSync(PFX_PATH)) {
  const pfxBuffer = fs.readFileSync(PFX_PATH);
  const httpsOptions = {
    pfx: pfxBuffer,
    passphrase: PFX_PASSWORD
  };
  const httpsServer = https.createServer(httpsOptions, handleRequest);
  httpsServer.listen(PORT_HTTPS, () => {
    console.log('HTTPS → https://localhost:' + PORT_HTTPS);
    console.log('');
    console.log('========================================');
    console.log('  Ouvre https://localhost:' + PORT_HTTPS);
    console.log('  (Accepte le certificat auto-signé)');
    console.log('========================================');
  });
}
