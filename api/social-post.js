// api/social-post.js — posts approved items from social/queue.json to X, Threads,
// Instagram and a Facebook Page. Run by the Vercel crons in vercel.json (noon and
// evening, Japan time).
//
// Safe by default:
//  - nothing is posted until SOCIAL_LIVE=true (otherwise it only logs what it would post)
//  - only items with "approved": true are posted
//  - a platform is used only once its keys are set, so platforms can be connected one at a time
//  - every post is logged in Firestore (socialLog/<item id>_<platform>) before it is sent,
//    so the same item never goes out twice; items more than 2 days late are skipped
//
// Environment variables (Vercel → shigematsu-tech → Settings → Environment Variables):
//   CRON_SECRET, FIREBASE_SERVICE_ACCOUNT, SOCIAL_LIVE
//   X:         X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET
//   Facebook:  FB_PAGE_ID, FB_PAGE_TOKEN
//   Instagram: IG_USER_ID (uses FB_PAGE_TOKEN)
//   Threads:   THREADS_USER_ID, THREADS_TOKEN (refreshed automatically every ~30 days)

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const SITE = "https://www.shigematsutech.com";
const GRAPH = `https://graph.facebook.com/${process.env.GRAPH_VERSION || "v23.0"}`;
const THREADS = "https://graph.threads.net/v1.0";
const MAX_LATE_DAYS = 2;
const MAX_TRIES = 3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function db() {
  if (!getApps().length) initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}")) });
  return getFirestore();
}

function jstNow() {
  const d = new Date(Date.now() + 9 * 3600e3);
  return { date: d.toISOString().slice(0, 10), hour: d.getUTCHours() };
}
const daysBetween = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 86400e3);

// ── platforms ───────────────────────────────────────────────────────────────
const PLATFORMS = {
  x: {
    ready: () => ["X_API_KEY", "X_API_SECRET", "X_ACCESS_TOKEN", "X_ACCESS_SECRET"].every((k) => process.env[k]),
    post: async (item) => {
      const text = item.link && !item.x.includes(item.link) ? `${item.x}\n${item.link}` : item.x;
      const url = "https://api.x.com/2/tweets";
      const r = await fetch(url, {
        method: "POST",
        headers: { Authorization: oauth1Header("POST", url), "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || j.title || JSON.stringify(j).slice(0, 200));
      return j.data?.id;
    },
  },
  facebook: {
    ready: () => process.env.FB_PAGE_ID && process.env.FB_PAGE_TOKEN,
    post: async (item) => {
      const form = { message: item.facebook, access_token: process.env.FB_PAGE_TOKEN };
      if (item.link) form.link = item.link;
      const j = await graph(`${GRAPH}/${process.env.FB_PAGE_ID}/feed`, form);
      return j.id;
    },
  },
  instagram: {
    ready: () => process.env.IG_USER_ID && process.env.FB_PAGE_TOKEN,
    needsImage: true,
    post: async (item) => {
      const token = process.env.FB_PAGE_TOKEN;
      const c = await graph(`${GRAPH}/${process.env.IG_USER_ID}/media`, { image_url: imageUrl(item), caption: item.instagram, access_token: token });
      for (let i = 0; i < 10; i++) {
        const s = await (await fetch(`${GRAPH}/${c.id}?fields=status_code&access_token=${encodeURIComponent(token)}`)).json();
        if (s.status_code === "FINISHED") break;
        if (s.status_code === "ERROR") throw new Error("Instagram could not process the image");
        await sleep(3000);
      }
      const p = await graph(`${GRAPH}/${process.env.IG_USER_ID}/media_publish`, { creation_id: c.id, access_token: token });
      return p.id;
    },
  },
  threads: {
    ready: () => process.env.THREADS_USER_ID && process.env.THREADS_TOKEN,
    post: async (item, store) => {
      const token = await threadsToken(store);
      const form = { text: item.threads, access_token: token };
      if (item.image) Object.assign(form, { media_type: "IMAGE", image_url: imageUrl(item) });
      else form.media_type = "TEXT";
      const c = await graph(`${THREADS}/${process.env.THREADS_USER_ID}/threads`, form);
      await sleep(item.image ? 20000 : 3000); // Threads asks for a pause before publishing
      const p = await graph(`${THREADS}/${process.env.THREADS_USER_ID}/threads_publish`, { creation_id: c.id, access_token: token });
      return p.id;
    },
  },
};

function imageUrl(item) {
  return /^https?:/.test(item.image) ? item.image : `${SITE}/${item.image.replace(/^\//, "")}`;
}

async function graph(url, form) {
  const r = await fetch(url, { method: "POST", body: new URLSearchParams(form) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(j.error?.message || `HTTP ${r.status}`);
  return j;
}

// Threads long-lived tokens last 60 days; refresh after 30 and keep the new one in Firestore.
async function threadsToken(store) {
  const ref = store.collection("socialConfig").doc("threads");
  const snap = await ref.get();
  let token = snap.exists ? snap.get("token") : process.env.THREADS_TOKEN;
  const refreshedAt = snap.exists ? snap.get("refreshedAt") : 0;
  if (Date.now() - refreshedAt > 30 * 86400e3) {
    try {
      const r = await fetch(`${THREADS.replace("/v1.0", "")}/refresh_access_token?grant_type=th_refresh_token&access_token=${encodeURIComponent(token)}`);
      const j = await r.json();
      if (j.access_token) {
        token = j.access_token;
        await ref.set({ token, refreshedAt: Date.now() });
      }
    } catch (e) {
      console.log("social: threads token refresh failed", String(e));
    }
  }
  return token;
}

// OAuth 1.0a signature for X (user context). JSON bodies are not part of the signature.
function oauth1Header(method, url) {
  const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  const p = {
    oauth_consumer_key: process.env.X_API_KEY,
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: process.env.X_ACCESS_TOKEN,
    oauth_version: "1.0",
  };
  const params = Object.keys(p).sort().map((k) => `${enc(k)}=${enc(p[k])}`).join("&");
  const base = [method, enc(url), enc(params)].join("&");
  const key = `${enc(process.env.X_API_SECRET)}&${enc(process.env.X_ACCESS_SECRET)}`;
  p.oauth_signature = crypto.createHmac("sha1", key).update(base).digest("base64");
  return "OAuth " + Object.keys(p).sort().map((k) => `${enc(k)}="${enc(p[k])}"`).join(", ");
}

// ── runner ──────────────────────────────────────────────────────────────────
function dueItems(queue, now) {
  const slotNow = now.hour < 15 ? "noon" : "evening";
  return queue.filter((it) => {
    if (it.approved !== true || !it.date) return false;
    const late = daysBetween(it.date, now.date);
    if (late < 0 || late > MAX_LATE_DAYS) return false;
    if (late === 0 && it.slot === "evening" && slotNow === "noon") return false;
    return true;
  });
}

module.exports = async (req, res) => {
  if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const live = process.env.SOCIAL_LIVE === "true";
  const queue = JSON.parse(fs.readFileSync(path.join(process.cwd(), "social", "queue.json"), "utf8"));
  const now = jstNow();
  const due = dueItems(queue, now);
  const enabled = Object.keys(PLATFORMS).filter((p) => PLATFORMS[p].ready());

  const plan = [];
  for (const item of due) {
    for (const p of enabled) {
      if (!item[p]) continue;                       // no text written for this platform
      if (PLATFORMS[p].needsImage && !item.image) continue;
      plan.push({ item, p });
    }
  }
  if (!live) {
    console.log("social DRY RUN:", JSON.stringify(plan.map(({ item, p }) => `${item.id} → ${p}`)), "enabled:", enabled.join(","));
    return res.json({ live: false, enabled, wouldPost: plan.map(({ item, p }) => `${item.id} → ${p}`) });
  }

  const store = db();
  const results = [];
  for (const { item, p } of plan) {
    const ref = store.collection("socialLog").doc(`${item.id}_${p}`);
    const snap = await ref.get();
    const prev = snap.exists ? snap.data() : null;
    if (prev && (prev.status === "posted" || prev.status === "posting")) continue;
    if (prev && (prev.tries || 0) >= MAX_TRIES) continue;
    await ref.set({ item: item.id, platform: p, status: "posting", tries: (prev?.tries || 0) + 1, at: FieldValue.serverTimestamp() }, { merge: true });
    try {
      const postId = await PLATFORMS[p].post(item, store);
      await ref.update({ status: "posted", postId: postId || null, error: FieldValue.delete() });
      results.push({ id: item.id, p, ok: true });
    } catch (e) {
      await ref.update({ status: "failed", error: String(e.message || e).slice(0, 300) });
      results.push({ id: item.id, p, ok: false, error: String(e.message || e) });
    }
  }
  console.log("social:", JSON.stringify(results));
  return res.json({ live: true, enabled, results });
};

module.exports.dueItems = dueItems;
module.exports.oauth1Header = oauth1Header;
