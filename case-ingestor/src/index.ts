export interface Env {
  DB: D1Database;
}

type EventMsg = {
  ts: number; ip: string; asn: number; country: string; ua: string;
  path: string; method: string; action: string; score: number; hits: number;
  zone: string; colo: string;
};

export default {
  async queue(batch: MessageBatch<EventMsg>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      const e = msg.body;
      // 1) upsert/open case keyed by (ip, asn, zone)
      const caseId = await upsertCase(env.DB, e);
      // 2) insert event
      await env.DB.prepare(
        `INSERT INTO events (case_id, ts, path, method, ua, action, score, hits, colo)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
      ).bind(caseId, e.ts, e.path, e.method, e.ua, e.action, e.score, e.hits, e.colo).run();

      // 3) recompute metrics & drafts when thresholds pass
      const metrics = await recomputeMetrics(env.DB, caseId);
      if (metrics.ef >= 50 || metrics.af >= 1 || metrics.bof < 1) {
        const abuse = buildAbuseReport(e.zone, metrics);
        const s504  = buildSection504Draft(metrics);
        await env.DB
          .prepare(`UPDATE cases SET
              last_seen=?2, status=?3, attack_rps=?4, est_bandwidth_mbps=?5,
              system_capacity_rps=?6, AF=?7, DF=?8, BoF=?9, evidence_count=?10,
              mercy=?11, justice=?12, abuse_report=?13, section504_draft=?14
            WHERE id=?1`)
          .bind(
            caseId, Date.now(), 'OPEN',
            metrics.attack_rps, metrics.bandwidth_mbps,
            metrics.capacity_rps, metrics.af, metrics.df, metrics.bof,
            metrics.ef, metrics.mercy, metrics.justice,
            abuse, s504
          ).run();
      }
      msg.ack();
    }
  }
}

async function upsertCase(DB: D1Database, e: EventMsg): Promise<string> {
  const key = `${e.zone}:${e.ip}:${e.asn}`;
  const found = await DB.prepare(`SELECT id FROM cases WHERE key = ?1`).bind(key).first<{id:string}>();
  if (found?.id) {
    await DB.prepare(`UPDATE cases SET last_seen=?2 WHERE id=?1`).bind(found.id, e.ts).run();
    return found.id;
  }
  const id = crypto.randomUUID();
  await DB.prepare(
    `INSERT INTO cases (id, key, zone, ip, asn, country, first_seen, last_seen, status)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'OPEN')`
  ).bind(id, key, e.zone, e.ip, e.asn, e.country, e.ts).run();
  return id;
}

async function recomputeMetrics(DB: D1Database, caseId: string) {
  // basic window: last 60s
  const now = Date.now(); const windowMs = 60_000;
  const from = now - windowMs;
  const rows = await DB.prepare(
    `SELECT ts, action, score, hits FROM events WHERE case_id=?1 AND ts>=?2 ORDER BY ts`
  ).bind(caseId, from).all<{ts:number, action:string, score:number, hits:number}>();
  const n = rows.results?.length ?? 0;

  // Attack Force (AF) estimate
  const rps = n / 60;                         // rough requests per second seen
  const estBandwidthMbps = (rps * 2 * 8) / 1024; // assume ~2KB/request avg -> Mbit/s
  const capacityRPS = 500; // tune to your origin capacity
  const AF = capacityRPS > 0 ? (rps / capacityRPS) : 0;

  // Defensive Force (DF) proxy: portion challenged+tarpitted+blocked (heavier weight)
  const challenged = rows.results?.filter(r => r.action === 'challenge').length ?? 0;
  const tarpitted  = rows.results?.filter(r => r.action === 'tarpit').length ?? 0;
  const blocked    = rows.results?.filter(r => r.action === 'block').length ?? 0;
  const allowed    = rows.results?.filter(r => r.action === 'allow').length ?? 0;
  const DF = (challenged*0.6 + tarpitted*0.9 + blocked*1.0) / 60;

  const BoF = AF > 0 ? (DF / AF) : 1;

  // Evidence Function (EF): count events window + severity weight (avg score)
  const avgScore = n ? (rows.results!.reduce((s,r)=>s + r.score,0)/n) : 0;
  const EF = Math.round(n + avgScore*3);

  // Mercy & Justice factors (0..1)
  // Mercy: more mercy for likely-infected residential (low score share) -> here inverse of avg score sigmoid
  const mercy = 1 / (1 + Math.exp((avgScore - 6))); // high score => low mercy
  // Justice: repeat offenses & non-allow share
  const nonAllow = n ? ((challenged + tarpitted + blocked) / n) : 0;
  const justice = Math.max(0, Math.min(1, nonAllow + (avgScore/12)));

  return {
    attack_rps: rps,
    bandwidth_mbps: estBandwidthMbps,
    capacity_rps: capacityRPS,
    af: AF, df: DF, bof: BoF,
    ef: EF, mercy, justice
  };
}

// ---------- Document builders ----------
function buildAbuseReport(zone: string, m: any) {
  return `ABUSE REPORT — ${zone}
Summary:
- Est. attack RPS: ${m.attack_rps.toFixed(2)}
- Est. bandwidth: ${m.bandwidth_mbps.toFixed(2)} Mbps
- AF (attack force): ${m.af.toFixed(2)}
- DF (defence force): ${m.df.toFixed(2)}
- BoF (balance): ${m.bof.toFixed(2)}
- Evidence count (60s): ${m.ef}

Request: Please investigate and mitigate sources associated with the enclosed evidence.
This is a good-faith report of interference with lawful computer use.`;
}

function buildSection504Draft(m: any) {
  const now = new Date().toISOString();
  return `SECTION 504 INFORMATION — Draft
I, [Your Name], believe on reasonable grounds that an indictable offence has been committed,
namely unauthorized use of computer and mischief in relation to data.

Facts (last 60s window):
- Estimated attack rate (RPS): ${m.attack_rps.toFixed(2)}
- Estimated bandwidth: ${m.bandwidth_mbps.toFixed(2)} Mbps
- AF: ${m.af.toFixed(2)}, DF: ${m.df.toFixed(2)}, BoF: ${m.bof.toFixed(2)}
- Evidence count: ${m.ef}

I request that this information be received and that process issue as the justice deems appropriate.
Date: ${now}
Signature: ________________________`;
}
