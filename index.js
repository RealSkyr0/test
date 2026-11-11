const G = 0.00006, BET_MS = 8000, GAP_MS = 4000, MAX_BET = 10000, START_BAL = 1000;
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const rnd = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const b64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...h } });

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
// Provably fair: crash (x100) = floor(99 / (1 - r)), r from HMAC-SHA256(seed, roundId). ~1% house edge.
async function crashPoint(seed, id) {
  const r = parseInt((await hmac(seed, String(id))).slice(0, 13), 16) / 2 ** 52;
  return Math.min(1e6, Math.max(100, Math.floor(99 / (1 - r))));
}
const latest = env => env.DB.prepare('SELECT * FROM rounds ORDER BY id DESC LIMIT 1').first();

async function settle(env, r) {
  const d = env.DB, id = r.id;
  await d.batch([
    d.prepare('UPDATE bets SET cashout=auto, payout=amount*auto/100 WHERE round_id=? AND cashout IS NULL AND auto IS NOT NULL AND auto<=?').bind(id, r.crash),
    d.prepare('UPDATE users SET balance=balance+(SELECT COALESCE(SUM(payout),0) FROM bets b WHERE b.user_id=users.id AND b.round_id=? AND b.credited=0) WHERE id IN (SELECT user_id FROM bets WHERE round_id=? AND credited=0 AND payout>0)').bind(id, id),
    d.prepare('UPDATE bets SET credited=1 WHERE round_id=? AND credited=0').bind(id),
  ]);
}
async function current(env, now) {
  let r = await latest(env);
  if (!r || now >= r.crash_ms + GAP_MS) {
    if (r) await settle(env, r);
    const id = r ? r.id + 1 : 1, seed = rnd(), crash = await crashPoint(seed, id);
    const run_start = now + BET_MS, crash_ms = run_start + Math.ceil(Math.log(crash / 100) / G);
    await env.DB.prepare('INSERT OR IGNORE INTO rounds(id,seed,seed_hash,crash,run_start,crash_ms) VALUES(?,?,?,?,?,?)')
      .bind(id, seed, await sha(seed), crash, run_start, crash_ms).run();
    r = await latest(env);
  }
  return r;
}

async function verifyGoogle(token, env) {
  const [h, p, s] = token.split('.');
  const head = JSON.parse(new TextDecoder().decode(b64(h)));
  if (head.alg !== 'RS256') throw 0;
  const keys = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = keys.keys.find(k => k.kid === head.kid); if (!jwk) throw 0;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64(s), enc.encode(h + '.' + p))) throw 0;
  const c = JSON.parse(new TextDecoder().decode(b64(p)));
  if (c.aud !== env.GOOGLE_CLIENT_ID || !['accounts.google.com', 'https://accounts.google.com'].includes(c.iss) || c.exp * 1000 < Date.now() || !c.sub) throw 0;
  return c;
}
async function getUser(req, env) {
  const m = /(?:^|; )__Host-sid=([0-9a-f]{64})/.exec(req.headers.get('cookie') || ''); if (!m) return null;
  return env.DB.prepare('SELECT u.id,u.name,u.balance FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.exp>?').bind(await sha(m[1]), Date.now()).first();
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), now = Date.now(), d = env.DB;
    if (req.method === 'GET' && url.pathname === '/') {
      const n = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
      return new Response(page(n, env.GOOGLE_CLIENT_ID), { headers: {
        'content-type': 'text/html;charset=utf-8',
        'content-security-policy': `default-src 'none'; script-src 'nonce-${n}' https://accounts.google.com/gsi/; style-src 'unsafe-inline' https://accounts.google.com/gsi/style; frame-src https://accounts.google.com/gsi/; connect-src 'self' https://accounts.google.com/gsi/; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cross-origin-opener-policy': 'same-origin-allow-popups' } });
    }
    if (!url.pathname.startsWith('/api/')) return new Response('Not found', { status: 404 });
    if (req.method === 'POST' && req.headers.get('origin') !== url.origin) return json({ error: 'bad origin' }, 403);

    if (url.pathname === '/api/state') {
      const r = await current(env, now), u = await getUser(req, env);
      const over = now >= r.crash_ms;
      const bet = u ? await d.prepare('SELECT amount,auto,cashout FROM bets WHERE user_id=? AND round_id=?').bind(u.id, r.id).first() : null;
      const hist = (await d.prepare('SELECT id,crash,seed,seed_hash FROM rounds WHERE crash_ms<=? ORDER BY id DESC LIMIT 10').bind(now).all()).results;
      return json({ now, id: r.id, hash: r.seed_hash, run_start: r.run_start, ...(over ? { crash: r.crash } : {}), user: u && { name: u.name, balance: u.balance }, bet, hist });
    }
    if (req.method !== 'POST') return json({ error: 'method' }, 405);
    let b = {}; try { b = await req.json(); } catch {}

    if (url.pathname === '/api/login') {
      let c; try { c = await verifyGoogle(String(b.credential || ''), env); } catch { return json({ error: 'invalid token' }, 401); }
      await d.prepare('INSERT INTO users(sub,name,balance) VALUES(?,?,?) ON CONFLICT(sub) DO UPDATE SET name=excluded.name').bind(c.sub, String(c.given_name || c.name || 'Player').slice(0, 30), START_BAL).run();
      const u = await d.prepare('SELECT id FROM users WHERE sub=?').bind(c.sub).first(), tok = rnd();
      await d.prepare('INSERT INTO sessions(hash,user_id,exp) VALUES(?,?,?)').bind(await sha(tok), u.id, now + 6048e5).run();
      return json({ ok: 1 }, 200, { 'set-cookie': `__Host-sid=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800` });
    }
    const u = await getUser(req, env); if (!u) return json({ error: 'sign in' }, 401);
    if (url.pathname === '/api/logout') {
      const t = /__Host-sid=([0-9a-f]{64})/.exec(req.headers.get('cookie') || '')[1];
      await d.prepare('DELETE FROM sessions WHERE hash=?').bind(await sha(t)).run();
      return json({ ok: 1 }, 200, { 'set-cookie': '__Host-sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });
    }
    if (url.pathname === '/api/refill') { // play money top-up when nearly broke
      await d.prepare('UPDATE users SET balance=? WHERE id=? AND balance<100').bind(START_BAL, u.id).run();
      return json({ ok: 1 });
    }
    const r = await current(env, now);
    if (url.pathname === '/api/bet') {
      const amt = b.amount, auto = b.auto == null || b.auto === '' ? null : b.auto;
      if (!Number.isInteger(amt) || amt < 1 || amt > MAX_BET) return json({ error: 'bad amount' }, 400);
      if (auto !== null && (!Number.isInteger(auto) || auto < 101 || auto > 1e6)) return json({ error: 'bad auto' }, 400);
      if (now >= r.run_start) return json({ error: 'betting closed' }, 409);
      const res = await d.batch([
        d.prepare('INSERT OR IGNORE INTO bets(user_id,round_id,amount,auto) SELECT ?,?,?,? WHERE ?<(SELECT run_start FROM rounds WHERE id=?) AND (SELECT balance FROM users WHERE id=?)>=?').bind(u.id, r.id, amt, auto, now, r.id, u.id, amt),
        d.prepare('UPDATE users SET balance=balance-(SELECT amount FROM bets WHERE user_id=? AND round_id=? AND charged=0) WHERE id=? AND EXISTS(SELECT 1 FROM bets WHERE user_id=? AND round_id=? AND charged=0)').bind(u.id, r.id, u.id, u.id, r.id),
        d.prepare('UPDATE bets SET charged=1 WHERE user_id=? AND round_id=? AND charged=0').bind(u.id, r.id),
      ]);
      return res[0].meta.changes ? json({ ok: 1 }) : json({ error: 'insufficient balance or already bet' }, 409);
    }
    if (url.pathname === '/api/cashout') {
      if (now < r.run_start || now >= r.crash_ms) return json({ error: 'too late' }, 409);
      const m = Math.min(r.crash, Math.floor(100 * Math.exp(G * (now - r.run_start))));
      const res = await d.batch([
        d.prepare('UPDATE bets SET cashout=?, payout=amount*?/100 WHERE user_id=? AND round_id=? AND cashout IS NULL AND charged=1').bind(m, m, u.id, r.id),
        d.prepare('UPDATE users SET balance=balance+(SELECT COALESCE(SUM(payout),0) FROM bets WHERE user_id=? AND round_id=? AND credited=0) WHERE id=?').bind(u.id, r.id, u.id),
        d.prepare('UPDATE bets SET credited=1 WHERE user_id=? AND round_id=? AND credited=0').bind(u.id, r.id),
      ]);
      return res[0].meta.changes ? json({ ok: 1, at: m }) : json({ error: 'no open bet' }, 409);
    }
    return json({ error: 'not found' }, 404);
  },
};

const page = (n, cid) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Crash (play money)</title>
<style>:root{color-scheme:dark light}body{font:16px system-ui;max-width:520px;margin:2rem auto;padding:0 1rem}#m{font-size:4rem;text-align:center;margin:.5rem 0}#st{text-align:center;opacity:.7}input,button{font:inherit;padding:.5rem;margin:.2rem}small{opacity:.6;word-break:break-all}.row{display:flex;gap:.3rem;flex-wrap:wrap}</style>
<h2>Crash <small>— play money only, no real value</small></h2>
<div id="who"></div>
<div id="login" hidden><div id="g"></div></div>
<div id="game" hidden>
<div id="m"></div><div id="st"></div><div id="bt" style="text-align:center"></div>
<div class="row"><input id="amt" type="number" min="1" max="10000" value="10" aria-label="Bet"><input id="auto" type="number" step="0.01" min="1.01" placeholder="Auto cash-out x" aria-label="Auto cash out">
<button id="bet">Bet</button><button id="co">Cash out</button></div>
<div class="row"><button id="refill">Top up (if under 100)</button><button id="out">Sign out</button></div>
<p><small id="hash"></small></p><h4>Recent rounds (verify: sha256(seed)=hash, crash=floor(99/(1-r)), r=first 13 hex of HMAC-SHA256(key=seed,msg=roundId)/2^52)</h4><div id="hist"></div></div>
<script nonce="${n}">
var G=${G},S=null,off=0,$=function(i){return document.getElementById(i)};
function api(p,b){return fetch(p,b!==undefined?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}:{}).then(function(r){return r.json()})}
function refresh(){return api('/api/state').then(function(s){S=s;off=s.now-Date.now();hist()})}
function hist(){var h=$('hist');h.textContent='';S.hist.forEach(function(r){var d=document.createElement('div');d.textContent='#'+r.id+'  '+(r.crash/100).toFixed(2)+'x  seed '+r.seed+'  hash '+r.seed_hash;d.style.fontSize='.7rem';d.style.wordBreak='break-all';d.style.margin='.4rem 0';h.appendChild(d)})}
function draw(){if(!S)return;var t=Date.now()+off,u=S.user;$('login').hidden=!!u;$('game').hidden=!u;$('who').textContent=u?u.name+' — '+u.balance+' chips':'';
var m,st,bet=t<S.run_start,run=false;
if(S.crash!==undefined){m=(S.crash/100).toFixed(2)+'x';st='CRASHED — next round soon';bet=false}
else if(bet){m='…';st='Betting closes in '+Math.ceil((S.run_start-t)/1000)+'s'}
else{m=Math.exp(G*(t-S.run_start)).toFixed(2)+'x';st='Running';run=true}
$('m').textContent=m;$('st').textContent=st;$('hash').textContent='Round #'+S.id+' commitment (sha256 of seed): '+S.hash;
var b=S.bet;$('bt').textContent=b?('Your bet: '+b.amount+(b.cashout?' — cashed out at '+(b.cashout/100).toFixed(2)+'x':(S.crash!==undefined?' — lost':''))):'';
$('bet').disabled=!bet||!!b;$('co').disabled=!(run&&b&&!b.cashout)}
function act(p,b){return api(p,b).then(function(r){if(r.error)alert(r.error);return refresh()})}
$('bet').onclick=function(){var a=parseFloat($('auto').value);act('/api/bet',{amount:parseInt($('amt').value,10),auto:isNaN(a)?null:Math.round(a*100)})};
$('co').onclick=function(){act('/api/cashout',{})};
$('refill').onclick=function(){act('/api/refill',{})};
$('out').onclick=function(){api('/api/logout',{}).then(refresh)};
function onCred(r){api('/api/login',{credential:r.credential}).then(function(x){if(x.error)alert(x.error);refresh()})}
window.onload=function(){google.accounts.id.initialize({client_id:${JSON.stringify(cid)},callback:onCred});google.accounts.id.renderButton($('g'),{theme:'outline',size:'large'})};
setInterval(refresh,500);(function f(){draw();requestAnimationFrame(f)})();refresh();
</script><script nonce="${n}" src="https://accounts.google.com/gsi/client" async defer></script></html>`;
