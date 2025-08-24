export interface Env {
  RATE_LIMITER: DurableObjectNamespace;
  ATTACK_EVENTS: Queue;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    const ip = request.headers.get('CF-Connecting-IP') ?? '0.0.0.0';
    const cf: any = (request as any).cf ?? {};
    const ua = request.headers.get('User-Agent') ?? '';
    const asn = cf.asn ?? 0;
    const country = cf.country ?? 'XX';
    const method = request.method;
    const path = url.pathname;

    // trusted health paths bypass
    if (path.startsWith('/healthz') || path.startsWith('/status')) {
      return fetch(request);
    }

    // challenge result endpoint
    if (path === '/__wasp/turnstile' && method === 'POST') {
      const form = await request.formData();
      const token = String(form.get('cf-turnstile-response') ?? '');
      const ok = await verifyTurnstile(env, token, ip);
      if (ok) {
        const res = new Response(null, { status: 303, headers: { Location: '/' } });
        res.headers.append('Set-Cookie', 'wasp_ok=1; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax');
        return res;
      }
      return challengePage(env.TURNSTILE_SITE_KEY, 'Verification failed. Try again.');
    }

    const cookies = parseCookies(request.headers.get('Cookie') ?? '');
    const trustedCookie = cookies['wasp_ok'] === '1';

    // Ask the Hive (Durable Object) for a verdict
    const id = env.RATE_LIMITER.idFromName(`${ip}:${asn}`);
    const stub = env.RATE_LIMITER.get(id);
    const verdictRes = await stub.fetch('https://do/limit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip, asn, ua, country, path, method, trustedCookie })
    });
    const { action, score, hits } = await verdictRes.json();

    // Emit an event to the Queue for case building (cheap, async)
    ctx.waitUntil(env.ATTACK_EVENTS.send({
      ts: Date.now(),
      ip, asn, country, ua, path, method,
      action, score, hits,
      zone: cf.zoneName ?? '',
      colo: cf.colo ?? '',
    }));

    if (action === 'allow') return fetch(request);
    if (action === 'challenge') return challengePage(env.TURNSTILE_SITE_KEY);
    if (action === 'tarpit') return tarpit(15000); // 15s slow-drip
    return new Response('Forbidden', { status: 403 });
  }
}

// ---------- Durable Object ----------
export class RateLimiter {
  state: DurableObjectState;
  constructor(state: DurableObjectState, _env: Env) { this.state = state; }

  async fetch(request: Request) {
    const { ip, asn, ua, path, method, trustedCookie } = await request.json();
    const now = Date.now();
    const key = `ip:${ip}`;
    let b = await this.state.storage.get<any>(key) ?? { hits: 0, window: now, score: 0, lastUA: '' };

    if (now - b.window > 1000) { b.hits = 0; b.window = now; }
    b.hits++;

    // heuristics
    const api = path.startsWith('/api/');
    const write = method !== 'GET' && method !== 'HEAD';
    let delta = 0;
    if (api && b.hits > 15) delta += 2;
    if (!api && b.hits > 35) delta += 1;
    if (!ua || ua === '-') delta += 1;
    if (write && b.hits > 5) delta += 2;
    if (b.lastUA && b.lastUA !== ua) delta += 1; // UA flapping
    b.lastUA = ua;
    b.score = Math.max(0, b.score + delta - 1); // decay

    await this.state.storage.put(key, b, { expirationTtl: 300 });

    let action: 'allow'|'challenge'|'tarpit'|'block' = 'allow';
    if (!trustedCookie) {
      if (b.hits > 120 || b.score > 12) action = 'block';
      else if (b.hits > 70 || b.score > 8) action = 'tarpit';
      else if (b.hits > 30 || b.score > 5) action = 'challenge';
    }
    return new Response(JSON.stringify({ action, score: b.score, hits: b.hits }), {
      headers: { 'content-type': 'application/json' }
    });
  }
}

// ---------- helpers ----------
function parseCookies(header: string) {
  const out: Record<string,string> = {};
  header.split(';').forEach(p => {
    const [k,v] = p.split('=');
    if (k && v) out[k.trim()] = decodeURIComponent(v.trim());
  });
  return out;
}
async function verifyTurnstile(env: Env, token: string, ip: string) {
  const fd = new FormData();
  fd.append('secret', env.TURNSTILE_SECRET);
  fd.append('response', token);
  fd.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });
  const data = await r.json();
  return !!data.success;
}
function challengePage(siteKey: string, msg?: string) {
  const html = `<!doctype html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WASP Check</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>body{font-family:system-ui;margin:0;display:grid;place-items:center;height:100vh}
form{padding:24px;border:1px solid #ddd;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,.05);max-width:360px}</style>
</head><body>
<form method="POST" action="/__wasp/turnstile">
<h3>Quick check</h3>
<p>${msg ?? 'Just proving you’re friendly.'}</p>
<div class="cf-turnstile" data-sitekey="${siteKey}"></div>
<br><button type="submit">Continue</button>
</form></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}
function tarpit(ms = 15000) {
  const { readable, writable } = new TransformStream();
  const w = writable.getWriter(); const enc = new TextEncoder();
  (async () => {
    const end = Date.now() + ms;
    while (Date.now() < end) { await w.write(enc.encode('.')); await new Promise(r => setTimeout(r, 1100)); }
    await w.close();
  })();
  return new Response(readable, { headers: { 'content-type': 'text/plain' } });
}
