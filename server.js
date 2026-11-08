import express from "express";
import axios from "axios";
import crypto from "node:crypto";
import fs from "node:fs/promises";

const PORT = 3000;
const API = "https://lagoslife.app/api";
const LL_DEV = process.env.LL_DEV || "234z515j6u1w0z5i";
const MAX_RETRIES = 9;
const RETRY_DELAY = 5_000;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const http = axios.create({ validateStatus: () => true, timeout: 30_000 });

const browserHeaders = {
  accept: "*/*",
  "content-type": "application/json",
  origin: "https://lagoslife.app",
  referer: "https://lagoslife.app/",
  "user-agent":
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
};

// ---------- Lagos Life login (server side only) ----------
function parseSetCookie(res) {
  const out = {};
  for (const line of res.headers["set-cookie"] || []) {
    const [pair] = line.split(";");
    const i = pair.indexOf("=");
    if (i > 0) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return out;
}

async function lagosLogin(username, password) {
  // 1. login -> ll_session
  const loginRes = await http.post(`${API}/auth/login`, { username, password }, {
    headers: { ...browserHeaders, cookie: `ll_dev=${LL_DEV}` }
  });
  if (loginRes.status >= 400) throw new Error(`Login failed: ${loginRes.status} ${JSON.stringify(loginRes.data)}`);
  const { ll_session } = parseSetCookie(loginRes);
  if (!ll_session) throw new Error("Login succeeded but no ll_session cookie was set");

  // 2. /auth/me with ll_dev + ll_session -> ll_pass
  const meRes = await http.get(`${API}/auth/me`, {
    headers: { ...browserHeaders, cookie: `ll_dev=${LL_DEV}; ll_session=${ll_session}` }
  });
  if (meRes.status >= 400) throw new Error(`/auth/me failed: ${meRes.status} ${JSON.stringify(meRes.data)}`);
  const { ll_pass } = parseSetCookie(meRes);
  if (!ll_pass) throw new Error("/auth/me did not set an ll_pass cookie");

  return { auth: { ll_session, ll_pass }, me: meRes.data };
}

// ---------- our own sessions ----------
// token -> { username, auth: {ll_session, ll_pass}, job }
const SESSIONS_FILE = "./sessions.json";
const newJob = () => ({ running: false, stop: false, logs: [], progress: {} });
const sessions = new Map();

// Load persisted sessions (username + Lagos Life cookies); jobs are runtime-only.
try {
  const saved = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf8"));
  for (const [token, v] of Object.entries(saved)) sessions.set(token, { ...v, job: newJob() });
} catch (e) {
  if (e.code !== "ENOENT") console.error("Could not read sessions.json:", e.message);
}

async function persistSessions() {
  const out = {};
  for (const [token, s] of sessions) out[token] = { username: s.username, auth: s.auth };
  await fs.writeFile(`${SESSIONS_FILE}.tmp`, JSON.stringify(out, null, 2), { mode: 0o600 });
  await fs.rename(`${SESSIONS_FILE}.tmp`, SESSIONS_FILE);
}

function readToken(req) {
  const m = /(?:^|;\s*)app_session=([a-f0-9]+)/.exec(req.headers.cookie || "");
  return m?.[1];
}

function requireSession(req, res, next) {
  const s = sessions.get(readToken(req));
  if (!s) return res.status(401).json({ error: "Not logged in" });
  req.s = s;
  next();
}

// ---------- persistent state (per user) ----------
const stateFile = s => `./balances.${s.username.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}.json`;
async function loadState(s) {
  try { return JSON.parse(await fs.readFile(stateFile(s), "utf8")); }
  catch (e) { if (e.code === "ENOENT") return {}; throw e; }
}
async function saveState(s, state) {
  await fs.writeFile(`${stateFile(s)}.tmp`, JSON.stringify(state, null, 2));
  await fs.rename(`${stateFile(s)}.tmp`, stateFile(s));
}

// ---------- job ----------
const log = (s, msg) => {
  s.job.logs.push(`[${new Date().toLocaleTimeString()}] ${msg}`);
  if (s.job.logs.length > 500) s.job.logs.shift();
};

const authedHeaders = (s, extra) => ({
  ...browserHeaders,
  origin: "https://lagoslife.app",
  referer: "https://lagoslife.app/",
  cookie: `ll_session=${s.auth.ll_session}; ll_pass=${s.auth.ll_pass}`,
  ...extra
});

async function interruptibleSleep(s, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end && !s.job.stop) await sleep(250);
}

async function resolveId(s, username) {
  const res = await http.get(`${API}/players`, { params: { q: username }, headers: authedHeaders(s) });
  if (res.status >= 400) throw new Error(`Lookup for "${username}" failed: ${res.status}`);
  const match = res.data.players?.find(p => p.username.toLowerCase() === username.toLowerCase());
  if (!match) throw new Error(`No exact match for username "${username}"`);
  log(s, `Resolved ${username} -> ${match.id} (${match.name})`);
  return match.id;
}

// Two-step (email code) flow. Pauses the job until the user submits the code via /api/2fa/code.
async function handleTwoFactor(s, info) {
  const job = s.job;
  const tf = (job.twofa = { to: info.to || "", waiting: true, error: "", code: null, resend: false });
  const call = body => http.post(`${API}/auth/2fa`, body, { headers: authedHeaders(s) });

  const requestCode = async () => {
    const r = await call({ action: "send" });
    log(s, `2FA send → ${r.status} ${JSON.stringify(r.data)}`);
    if (r.data?.sent) { tf.to = r.data.to || tf.to; tf.error = ""; }
    else tf.error = r.data?.error || `Could not send the code (${r.status})`;
  };

  log(s, `Two-step code required (${info.method || "email"}) — sending code…`);
  await requestCode();

  while (!job.stop) {
    if (tf.resend) { tf.resend = false; await requestCode(); }
    if (tf.code) {
      const code = tf.code; tf.code = null;
      const r = await call({ action: "step", code });
      log(s, `2FA verify → ${r.status} ${JSON.stringify(r.data)}`);
      if (r.data?.ok) {
        // Keep any refreshed cookies the server hands back
        const fresh = parseSetCookie(r);
        if (fresh.ll_session) s.auth.ll_session = fresh.ll_session;
        if (fresh.ll_pass) s.auth.ll_pass = fresh.ll_pass;
        if (fresh.ll_session || fresh.ll_pass) await persistSessions();
        job.twofa = null;
        return;
      }
      tf.error = r.data?.error || `Verification failed (${r.status})`;
    }
    await sleep(300);
  }
  job.twofa = null;
  throw new Error("Stopped");
}

async function send(s, to, amount, transactionId, pin) {
  let twoFactorRounds = 0;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    if (s.job.stop) throw new Error("Stopped");
    try {
      log(s, `Attempt ${attempt}/${MAX_RETRIES}: sending ${amount}`);
      const res = await http.post(`${API}/send`, { to, amount: Number(amount), pin }, {
        headers: authedHeaders(s, { "idempotency-key": transactionId })
      });
      log(s, `${amount} → ${res.status} ${JSON.stringify(res.data)}`);
      if (res.status >= 200 && res.status < 300) return;
      if (res.data?.code === "two_factor_step") {
        if (++twoFactorRounds > 3) throw new Error("Two-step verification keeps being requested");
        await handleTwoFactor(s, res.data);
        attempt--; // verification isn't a failed attempt; retry the same send (same idempotency key)
        continue;
      }
    } catch (e) {
      if (e.message === "Stopped" || e.message.startsWith("Two-step")) throw e;
      log(s, `Network error on attempt ${attempt}: ${e.code ?? e.message}`);
    }
    if (attempt < MAX_RETRIES) await interruptibleSleep(s, RETRY_DELAY);
  }
  throw new Error(`Send failed after ${MAX_RETRIES} attempts`);
}

async function runJob(s, { recipients, total, perTransaction, delay, pin }) {
  const job = s.job;
  job.running = true; job.stop = false; job.logs = []; job.progress = {};
  try {
    const state = await loadState(s);
    const TOTAL = BigInt(total), PER = BigInt(perTransaction);
    const share = TOTAL / BigInt(recipients.length);
    const remainder = TOTAL - share * BigInt(recipients.length);

    for (const u of recipients) job.progress[u.toLowerCase()] = { username: u, remaining: null, target: null, done: false };

    for (let i = 0; i < recipients.length && !job.stop; i++) {
      const username = recipients[i], key = username.toLowerCase();
      const target = i === recipients.length - 1 ? share + remainder : share;

      if (!state[key]) {
        state[key] = { id: await resolveId(s, username), target: target.toString(), remaining: target.toString(), transaction: 0 };
        await saveState(s, state);
      } else if (BigInt(state[key].remaining) === 0n || state[key].target !== target.toString()) {
        // Previous run finished, or you changed the amount: start a fresh run.
        // `transaction` is NOT reset, so idempotency keys never repeat across runs.
        log(s, `${username}: starting a new run (target ${target})`);
        state[key].target = target.toString();
        state[key].remaining = target.toString();
        await saveState(s, state);
      }
      const entry = state[key];
      let remaining = BigInt(entry.remaining), transaction = entry.transaction;
      const prog = job.progress[key];
      prog.target = entry.target; prog.remaining = remaining.toString();

      log(s, `=== [${i + 1}/${recipients.length}] ${username} (${entry.id}) — remaining ${remaining}`);

      while (remaining > 0n && !job.stop) {
        transaction++;
        const amount = remaining >= PER ? PER : remaining;
        await send(s, entry.id, amount, `${entry.id}-${transaction}`, pin);

        remaining -= amount;
        entry.remaining = remaining.toString(); entry.transaction = transaction;
        await saveState(s, state);
        prog.remaining = entry.remaining;

        if (remaining > 0n || i < recipients.length - 1) {
          log(s, `Waiting ${delay / 1000}s...`);
          await interruptibleSleep(s, delay);
        }
      }
      if (remaining === 0n) { prog.done = true; log(s, `Done with ${username}.`); }
    }
    log(s, job.stop ? "Stopped." : "Finished.");
  } catch (e) {
    log(s, `ERROR: ${e.message}`);
  } finally {
    job.twofa = null;
    job.running = false;
  }
}

// ---------- routes ----------
const app = express();
app.use(express.json());
app.use(express.static("public"));

// Frontend -> our API. We log into Lagos Life here and hand the browser only our own token.
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const { auth, me } = await lagosLogin(username, password);
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { username, auth, job: newJob() });
    await persistSessions();
    res.setHeader("Set-Cookie", `app_session=${token}; HttpOnly; SameSite=Strict; Path=/`);
    res.json({ ok: true, me });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});

app.post("/api/logout", async (req, res) => {
  const t = readToken(req), s = sessions.get(t);
  if (s) s.job.stop = true;
  sessions.delete(t);
  await persistSessions();
  res.setHeader("Set-Cookie", "app_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.post("/api/start", requireSession, (req, res) => {
  const s = req.s;
  if (s.job.running) return res.status(409).json({ error: "Already running" });
  try {
    const { recipients, total, perTransaction, delay, pin } = req.body;
    if (!recipients?.length) throw new Error("No recipients");
    if (!pin) throw new Error("PIN required");
    BigInt(total); BigInt(perTransaction);
    runJob(s, { recipients, total, perTransaction, delay: Number(delay) || 31_000, pin: String(pin) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/stop", requireSession, (req, res) => { req.s.job.stop = true; res.json({ ok: true }); });

app.post("/api/2fa/code", requireSession, (req, res) => {
  const tf = req.s.job.twofa, code = String(req.body.code || "").trim();
  if (!tf) return res.status(409).json({ error: "No code is being requested right now" });
  if (!/^\d{4,8}$/.test(code)) return res.status(400).json({ error: "Enter the numeric code from your email" });
  tf.error = ""; tf.code = code;
  res.json({ ok: true });
});

app.post("/api/2fa/resend", requireSession, (req, res) => {
  const tf = req.s.job.twofa;
  if (!tf) return res.status(409).json({ error: "No code is being requested right now" });
  tf.resend = true;
  res.json({ ok: true });
});

app.get("/api/status", (req, res) => {
  const s = sessions.get(readToken(req));
  if (!s) return res.json({ loggedIn: false, running: false, logs: [], progress: [] });
  res.json({ loggedIn: true, username: s.username, running: s.job.running, twofa: s.job.twofa ? { to: s.job.twofa.to, error: s.job.twofa.error, verifying: !!s.job.twofa.code } : null, logs: s.job.logs, progress: Object.values(s.job.progress) });
});

app.listen(PORT, "127.0.0.1", () => console.log(`http://localhost:${PORT}`));
