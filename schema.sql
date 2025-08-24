-- Schema for Divine Court D1 database

CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  key TEXT UNIQUE,
  zone TEXT,
  ip TEXT,
  asn INTEGER,
  country TEXT,
  first_seen INTEGER,
  last_seen INTEGER,
  status TEXT,
  attack_rps REAL DEFAULT 0,
  est_bandwidth_mbps REAL DEFAULT 0,
  system_capacity_rps REAL DEFAULT 0,
  AF REAL DEFAULT 0,
  DF REAL DEFAULT 0,
  BoF REAL DEFAULT 1,
  evidence_count INTEGER DEFAULT 0,
  mercy REAL DEFAULT 0.5,
  justice REAL DEFAULT 0.5,
  abuse_report TEXT,
  section504_draft TEXT
);

CREATE INDEX IF NOT EXISTS idx_cases_key ON cases(key);
CREATE INDEX IF NOT EXISTS idx_cases_last ON cases(last_seen);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT,
  ts INTEGER,
  path TEXT,
  method TEXT,
  ua TEXT,
  action TEXT,
  score REAL,
  hits INTEGER,
  colo TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_events_case_ts ON events(case_id, ts);
