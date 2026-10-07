'use strict';
// 카카오 로그인 선착순 참가 투표 서버 (의존성 없음, Node 18+)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- 설정 ----------
(function loadEnv() {
  const p = path.join(__dirname, '.env');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

const PORT = Number(process.env.PORT) || 3000;
// Render는 RENDER_EXTERNAL_URL을 자동으로 넣어줌
const BASE_URL = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const KAKAO_REST_KEY = process.env.KAKAO_REST_API_KEY || '';
const KAKAO_CLIENT_SECRET = process.env.KAKAO_CLIENT_SECRET || '';
const KAKAO_JS_KEY = process.env.KAKAO_JS_KEY || '';
const DEV_MODE = process.env.DEV_MODE === '1';
const SECRET = process.env.SESSION_SECRET || (DEV_MODE ? 'dev-only-secret' : crypto.randomBytes(32).toString('hex'));
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const REDIRECT_URI = BASE_URL + '/oauth/kakao/callback';
const SECURE_COOKIE = BASE_URL.startsWith('https://');
const DAYS = ['월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일'];
const DEFAULT_CAPACITY = 10;
const DEFAULT_WAITLIST = 2;

if (!process.env.SESSION_SECRET && !DEV_MODE) console.warn('SESSION_SECRET이 없어 임시 값을 씁니다. (재시작하면 다시 로그인 필요)');
if (!KAKAO_REST_KEY && !DEV_MODE) console.warn('KAKAO_REST_API_KEY가 없어 로그인이 동작하지 않습니다.');

// ---------- 저장소 (JSON 파일) ----------
let db = { polls: {} };
if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
function save() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// ---------- 유틸 ----------
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function sign(obj) {
  const p = Buffer.from(JSON.stringify(obj)).toString('base64url');
  return p + '.' + hmac(p);
}
function verify(tok) {
  if (!tok) return null;
  const [p, s] = tok.split('.');
  if (!p || !s) return null;
  const expect = hmac(p);
  if (s.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expect))) return null;
  try {
    const o = JSON.parse(Buffer.from(p, 'base64url').toString());
    return o.exp && o.exp < Date.now() ? null : o;
  } catch { return null; }
}
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function cookie(name, value, maxAgeSec) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}` + (SECURE_COOKIE ? '; Secure' : '');
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e4) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(data))));
    req.on('error', reject);
  });
}
const safeNext = (n) => (typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') ? n : '/');
const newId = () => crypto.randomBytes(6).toString('base64url');
const clampInt = (v, min, max, def) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def; };

const MESSAGES = {
  joined: '참가 완료! 확정 명단에 들어갔어요.',
  waiting: '정원이 차서 대기 명단에 들어갔어요. 취소자가 생기면 자동으로 확정돼요.',
  left: '참가를 취소했어요.',
  already: '이미 신청했어요. (1인 1회)',
  full: '마감되었어요. 정원과 대기 모두 찼어요.',
  closed: '투표가 마감 처리되었어요.',
  saved: '설정을 저장했어요.',
  toosmall: '현재 신청자 수보다 정원+대기를 작게 줄일 수 없어요.',
  kicked: '해당 참가자를 명단에서 뺐어요.',
  loginfail: '카카오 로그인에 실패했어요. 다시 시도해 주세요.',
};

// ---------- 화면 ----------
function layout(title, body, { og, user } = {}) {
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
${og ? `<meta property="og:title" content="${esc(og.title)}"><meta property="og:description" content="${esc(og.description)}"><meta property="og:url" content="${esc(og.url)}"><meta property="og:type" content="website">` : ''}
<style>
:root{--bg:#f6f6f4;--card:#fff;--text:#1d1d1f;--muted:#6b6b70;--line:#e4e4e0;--accent:#3b5bdb;--ok:#2b8a3e;--wait:#e8590c;--bad:#c92a2a}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1e1e21;--text:#ececef;--muted:#9a9aa2;--line:#2e2e33;--accent:#7b93f0;--ok:#51cf66;--wait:#ff922b;--bad:#ff6b6b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 -apple-system,"Apple SD Gothic Neo","Malgun Gothic",sans-serif}
main{max-width:520px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:14px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:0 0 10px}
.muted{color:var(--muted);font-size:14px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;font-size:14px}
a{color:var(--accent)}
label{display:block;font-size:14px;color:var(--muted);margin:10px 0 4px}
input,select{width:100%;padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font-size:16px}
.row{display:flex;gap:10px}.row>*{flex:1}
button,.btn{display:block;width:100%;padding:13px;border:0;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-top:12px;background:var(--accent);color:#fff}
.kakao{background:#FEE500;color:#191919}
.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
.mini{display:inline;width:auto;padding:2px 8px;margin:0;font-size:12px;font-weight:500}
.msg{padding:12px 14px;border-radius:10px;background:var(--card);border-left:4px solid var(--accent);margin-bottom:14px;font-size:15px}
.stats{display:flex;gap:10px;margin-top:12px}.stat{flex:1;border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center}
.stat b{display:block;font-size:22px}
ol{margin:0;padding-left:22px}li{padding:5px 0;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:8px}
li:last-child{border-bottom:0}ol li{display:list-item}ol li .r{float:right}
.badge{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid currentColor}
.ok{color:var(--ok)}.wait{color:var(--wait)}.bad{color:var(--bad)}
details summary{cursor:pointer;font-weight:600}
</style></head><body><main>
${user ? `<div class="top"><a href="/">내 투표</a><span>${esc(user.name)}님 · <a href="/logout">로그아웃</a></span></div>` : ''}
${body}
</main></body></html>`;
}

function loginButton(next) {
  return `<a class="btn kakao" href="/login?next=${encodeURIComponent(next)}">카카오로 로그인</a>`;
}

function homePage(user, msg) {
  if (!user) {
    return layout('선착순 투표', `<div class="card"><h1>선착순 참가 투표</h1>
<p class="muted">요일·시간·인원을 정해 투표를 만들고, 링크를 카카오톡 방에 공유하세요. 카카오 계정당 1명만 신청할 수 있어요.</p>
${loginButton('/')}</div>`);
  }
  const mine = Object.values(db.polls).filter((p) => p.ownerId === user.uid).sort((a, b) => b.createdAt - a.createdAt);
  const list = mine.length
    ? `<ul style="padding:0;margin:0;list-style:none">${mine.map((p) => `<li><a href="/p/${p.id}">${esc(p.title)}</a><span class="muted">${esc(p.day)} ${esc(p.time)} · ${Math.min(p.entries.length, p.capacity)}/${p.capacity}</span></li>`).join('')}</ul>`
    : '<p class="muted">아직 만든 투표가 없어요.</p>';
  return layout('선착순 투표', `${msg ? `<div class="msg">${esc(msg)}</div>` : ''}
<form class="card" method="post" action="/polls"><h2>새 투표 만들기</h2>
<label>제목</label><input name="title" maxlength="60" required placeholder="예: 목요일 저녁 풋살">
<div class="row"><div><label>요일</label><select name="day">${DAYS.map((d) => `<option>${d}</option>`).join('')}</select></div>
<div><label>시간</label><input type="time" name="time" required value="19:00"></div></div>
<div class="row"><div><label>인원 (선착순)</label><input type="number" name="capacity" min="1" max="100" value="${DEFAULT_CAPACITY}" required></div>
<div><label>대기 인원</label><input type="number" name="waitlist" min="0" max="50" value="${DEFAULT_WAITLIST}" required></div></div>
<label>메모 (선택)</label><input name="note" maxlength="120" placeholder="장소, 회비 등">
<button>투표 만들기</button></form>
<div class="card"><h2>내가 만든 투표</h2>${list}</div>`, { user });
}

function pollPage(poll, user, msg) {
  const confirmed = poll.entries.slice(0, poll.capacity);
  const waiting = poll.entries.slice(poll.capacity, poll.capacity + poll.waitlist);
  const myIdx = user ? poll.entries.findIndex((e) => e.uid === user.uid) : -1;
  const isOwner = user && user.uid === poll.ownerId;
  const total = poll.capacity + poll.waitlist;
  const full = poll.entries.length >= total;
  const url = `${BASE_URL}/p/${poll.id}`;

  let myStatus = '';
  if (myIdx >= 0) {
    myStatus = myIdx < poll.capacity
      ? `<p><span class="badge ok">확정</span> ${myIdx + 1}번째로 참가했어요.</p>`
      : `<p><span class="badge wait">대기 ${myIdx - poll.capacity + 1}번</span> 확정자가 취소하면 자동으로 올라가요.</p>`;
  }

  let action;
  if (!user) action = loginButton(`/p/${poll.id}`);
  else if (myIdx >= 0) action = `<form method="post" action="/p/${poll.id}/leave" onsubmit="return confirm('참가를 취소할까요?')"><button class="ghost">참가 취소</button></form>`;
  else if (poll.closed) action = `<button disabled class="ghost">마감된 투표예요</button>`;
  else if (full) action = `<button disabled class="ghost">정원·대기 모두 마감</button>`;
  else action = `<form method="post" action="/p/${poll.id}/join"><button>${poll.entries.length < poll.capacity ? '참가하기' : '대기 신청하기'}</button></form>`;

  const kick = (e) => isOwner && e.uid !== user.uid
    ? `<form class="r" method="post" action="/p/${poll.id}/kick" style="display:inline" onsubmit="return confirm('${esc(e.name)}님을 명단에서 뺄까요?')"><input type="hidden" name="uid" value="${esc(e.uid)}"><button class="mini danger">빼기</button></form>`
    : '';
  const row = (e) => `<li>${esc(e.name)}${user && e.uid === user.uid ? ' <b>(나)</b>' : ''}${kick(e)}</li>`;

  const ownerPanel = isOwner ? `<div class="card"><details><summary>관리 (만든 사람만 보여요)</summary>
<form method="post" action="/p/${poll.id}/edit">
<label>제목</label><input name="title" maxlength="60" required value="${esc(poll.title)}">
<div class="row"><div><label>요일</label><select name="day">${DAYS.map((d) => `<option${d === poll.day ? ' selected' : ''}>${d}</option>`).join('')}</select></div>
<div><label>시간</label><input type="time" name="time" required value="${esc(poll.time)}"></div></div>
<div class="row"><div><label>인원</label><input type="number" name="capacity" min="1" max="100" value="${poll.capacity}"></div>
<div><label>대기 인원</label><input type="number" name="waitlist" min="0" max="50" value="${poll.waitlist}"></div></div>
<label>메모</label><input name="note" maxlength="120" value="${esc(poll.note)}">
<button>저장</button></form>
<form method="post" action="/p/${poll.id}/close"><button class="ghost">${poll.closed ? '다시 열기' : '마감하기'}</button></form>
<form method="post" action="/p/${poll.id}/delete" onsubmit="return confirm('투표를 삭제할까요? 되돌릴 수 없어요.')"><button class="danger">투표 삭제</button></form>
</details></div>` : '';

  const shareJs = KAKAO_JS_KEY ? `<script src="https://t1.kakaocdn.net/kakao_js_sdk/2.7.2/kakao.min.js" crossorigin="anonymous"></script>
<script>try{Kakao.init(${JSON.stringify(KAKAO_JS_KEY)})}catch(e){}
function kshare(){Kakao.Share.sendDefault({objectType:'text',text:${JSON.stringify(`[선착순 ${poll.capacity}명] ${poll.title}\n${poll.day} ${poll.time}`)},link:{mobileWebUrl:${JSON.stringify(url)},webUrl:${JSON.stringify(url)}},buttonTitle:'참가하기'})}</script>
<button class="kakao" onclick="kshare()">카카오톡으로 공유</button>` : '';

  const body = `${msg ? `<div class="msg">${esc(msg)}</div>` : ''}
<div class="card"><h1>${esc(poll.title)}</h1>
<div>${esc(poll.day)} ${esc(poll.time)}${poll.closed ? ' <span class="badge bad">마감</span>' : ''}</div>
${poll.note ? `<div class="muted">${esc(poll.note)}</div>` : ''}
<div class="muted">만든 사람: ${esc(poll.ownerName)}</div>
<div class="stats"><div class="stat"><b class="ok">${confirmed.length}/${poll.capacity}</b><span class="muted">확정</span></div>
<div class="stat"><b class="wait">${waiting.length}/${poll.waitlist}</b><span class="muted">대기</span></div></div>
${myStatus}${action}</div>
<div class="card"><h2>확정 명단</h2>${confirmed.length ? `<ol>${confirmed.map(row).join('')}</ol>` : '<p class="muted">아직 아무도 없어요. 첫 번째로 참가해 보세요!</p>'}</div>
${poll.waitlist > 0 ? `<div class="card"><h2>대기 명단</h2>${waiting.length ? `<ol>${waiting.map(row).join('')}</ol>` : '<p class="muted">대기자 없음</p>'}</div>` : ''}
<div class="card"><button class="ghost" onclick="navigator.clipboard.writeText(${esc(JSON.stringify(url))}).then(()=>alert('링크를 복사했어요. 카톡방에 붙여넣으세요.'))">링크 복사</button>${shareJs}
<a class="btn ghost" href="/p/${poll.id}">새로고침</a></div>
${ownerPanel}`;
  return layout(poll.title, body, {
    user,
    og: { title: `[선착순 ${poll.capacity}명] ${poll.title}`, description: `${poll.day} ${poll.time} · 현재 ${confirmed.length}/${poll.capacity}명, 대기 ${waiting.length}/${poll.waitlist}`, url },
  });
}

// ---------- 요청 처리 ----------
function send(res, status, html, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(html);
}
function redirect(res, to, headers = {}) {
  res.writeHead(303, { Location: to, ...headers });
  res.end();
}
function pollFields(b) {
  return {
    title: String(b.title || '').trim().slice(0, 60) || '선착순 모임',
    day: DAYS.includes(b.day) ? b.day : DAYS[0],
    time: /^\d{2}:\d{2}$/.test(b.time) ? b.time : '19:00',
    capacity: clampInt(b.capacity, 1, 100, DEFAULT_CAPACITY),
    waitlist: clampInt(b.waitlist, 0, 50, DEFAULT_WAITLIST),
    note: String(b.note || '').trim().slice(0, 120),
  };
}

async function handle(req, res) {
  const u = new URL(req.url, BASE_URL);
  const cookies = parseCookies(req);
  const user = verify(cookies.sid);
  const msg = MESSAGES[u.searchParams.get('m')] || '';
  const method = req.method;
  const p = u.pathname;

  if (method === 'GET' && p === '/') return send(res, 200, homePage(user, msg));

  // --- 로그인 ---
  if (method === 'GET' && p === '/login') {
    const next = safeNext(u.searchParams.get('next'));
    if (!KAKAO_REST_KEY && !DEV_MODE) {
      return send(res, 200, layout('설정 필요', `<div class="card"><h1>아직 준비 중이에요</h1>
<p class="muted">서버에 KAKAO_REST_API_KEY가 설정되지 않았어요. 관리자가 카카오 앱 키를 넣으면 로그인할 수 있어요.</p></div>`));
    }
    if (!KAKAO_REST_KEY) { // DEV_MODE 전용 가짜 로그인
      return send(res, 200, layout('테스트 로그인', `<form class="card" method="post" action="/dev-login"><h2>테스트 로그인 (DEV_MODE)</h2>
<p class="muted">카카오 키가 없어 테스트용 로그인을 사용해요.</p><input type="hidden" name="next" value="${esc(next)}">
<label>이름</label><input name="name" required maxlength="20"><button>로그인</button></form>`));
    }
    const nonce = crypto.randomBytes(12).toString('base64url');
    const state = sign({ next, nonce, exp: Date.now() + 10 * 60e3 });
    const auth = new URL('https://kauth.kakao.com/oauth/authorize');
    auth.search = new URLSearchParams({ client_id: KAKAO_REST_KEY, redirect_uri: REDIRECT_URI, response_type: 'code', state }).toString();
    return redirect(res, auth.toString(), { 'Set-Cookie': cookie('oauth_nonce', nonce, 600) });
  }

  if (method === 'GET' && p === '/oauth/kakao/callback') {
    const st = verify(u.searchParams.get('state'));
    const code = u.searchParams.get('code');
    if (!st || !code || st.nonce !== cookies.oauth_nonce) return redirect(res, '/?m=loginfail');
    try {
      const params = new URLSearchParams({ grant_type: 'authorization_code', client_id: KAKAO_REST_KEY, redirect_uri: REDIRECT_URI, code });
      if (KAKAO_CLIENT_SECRET) params.set('client_secret', KAKAO_CLIENT_SECRET);
      const tr = await fetch('https://kauth.kakao.com/oauth/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8' }, body: params,
      });
      const tj = await tr.json();
      if (!tj.access_token) throw new Error('token: ' + JSON.stringify(tj));
      const ur = await fetch('https://kapi.kakao.com/v2/user/me', { headers: { Authorization: 'Bearer ' + tj.access_token } });
      const ku = await ur.json();
      if (!ku.id) throw new Error('user: ' + JSON.stringify(ku));
      const name = ku.kakao_account?.profile?.nickname || ku.properties?.nickname || '카카오사용자';
      const sid = sign({ uid: 'kakao:' + ku.id, name, exp: Date.now() + 30 * 86400e3 });
      return redirect(res, safeNext(st.next), { 'Set-Cookie': [cookie('sid', sid, 30 * 86400), cookie('oauth_nonce', '', 0)] });
    } catch (e) {
      console.error('Kakao login error:', e.message);
      return redirect(res, '/?m=loginfail');
    }
  }

  if (method === 'POST' && p === '/dev-login' && DEV_MODE && !KAKAO_REST_KEY) {
    const b = await readBody(req);
    const name = String(b.name || '').trim().slice(0, 20) || '테스트';
    const sid = sign({ uid: 'dev:' + name, name, exp: Date.now() + 86400e3 });
    return redirect(res, safeNext(b.next), { 'Set-Cookie': cookie('sid', sid, 86400) });
  }

  if (p === '/logout') return redirect(res, '/', { 'Set-Cookie': cookie('sid', '', 0) });

  // --- 투표 만들기 ---
  if (method === 'POST' && p === '/polls') {
    if (!user) return redirect(res, '/login?next=/');
    const b = await readBody(req);
    const poll = { id: newId(), ...pollFields(b), ownerId: user.uid, ownerName: user.name, createdAt: Date.now(), closed: false, entries: [] };
    db.polls[poll.id] = poll;
    save();
    return redirect(res, `/p/${poll.id}`);
  }

  // --- 투표 페이지 / 동작 ---
  const m = p.match(/^\/p\/([\w-]+)(?:\/(join|leave|edit|close|delete|kick))?$/);
  if (m) {
    const poll = db.polls[m[1]];
    if (!poll) return send(res, 404, layout('없는 투표', '<div class="card"><h1>투표를 찾을 수 없어요</h1><p class="muted">삭제되었거나 잘못된 링크예요.</p><a class="btn" href="/">처음으로</a></div>'));
    const action = m[2];
    const back = (code) => redirect(res, `/p/${poll.id}${code ? '?m=' + code : ''}`);

    if (method === 'GET' && !action) return send(res, 200, pollPage(poll, user, msg));
    if (method !== 'POST' || !action) return send(res, 405, 'Method Not Allowed');
    if (!user) return redirect(res, `/login?next=/p/${poll.id}`);
    const b = await readBody(req);

    // Node는 단일 스레드라 아래 검사와 추가 사이에 다른 요청이 끼어들지 않음 → 선착순 보장
    if (action === 'join') {
      if (poll.entries.some((e) => e.uid === user.uid)) return back('already');
      if (poll.closed) return back('closed');
      if (poll.entries.length >= poll.capacity + poll.waitlist) return back('full');
      poll.entries.push({ uid: user.uid, name: user.name, at: Date.now() });
      save();
      return back(poll.entries.length <= poll.capacity ? 'joined' : 'waiting');
    }
    if (action === 'leave') {
      poll.entries = poll.entries.filter((e) => e.uid !== user.uid);
      save();
      return back('left');
    }

    if (user.uid !== poll.ownerId) return send(res, 403, layout('권한 없음', '<div class="card">만든 사람만 할 수 있어요.</div>'));
    if (action === 'edit') {
      const f = pollFields(b);
      if (f.capacity + f.waitlist < poll.entries.length) return back('toosmall');
      Object.assign(poll, f);
      save();
      return back('saved');
    }
    if (action === 'close') { poll.closed = !poll.closed; save(); return back(); }
    if (action === 'kick') { poll.entries = poll.entries.filter((e) => e.uid !== b.uid); save(); return back('kicked'); }
    if (action === 'delete') { delete db.polls[poll.id]; save(); return redirect(res, '/'); }
  }

  send(res, 404, layout('404', '<div class="card">페이지를 찾을 수 없어요. <a href="/">처음으로</a></div>'));
}

http.createServer((req, res) => {
  handle(req, res).catch((e) => { console.error(e); if (!res.headersSent) send(res, 500, '서버 오류'); });
}).listen(PORT, () => {
  console.log(`실행 중: ${BASE_URL}  (Kakao Redirect URI: ${REDIRECT_URI})${DEV_MODE && !KAKAO_REST_KEY ? '  [DEV_MODE 테스트 로그인]' : ''}`);
});
