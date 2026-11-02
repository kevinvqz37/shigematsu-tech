// api/social-status.js — a simple page showing what the social bot has posted.
// Open shigematsutech.com/api/social-status on any phone. Read-only; shows only
// the queue's dates/products and each post's result (no keys, no text).
const fs = require("fs");
const path = require("path");
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const PLATFORMS = ["x", "threads", "instagram", "facebook"];

module.exports = async (req, res) => {
  let rows = "", note = "";
  try {
    const queue = JSON.parse(fs.readFileSync(path.join(process.cwd(), "social", "queue.json"), "utf8"));
    const enabled = {
      x: ["X_API_KEY", "X_API_SECRET", "X_ACCESS_TOKEN", "X_ACCESS_SECRET"].every((k) => process.env[k]),
      facebook: !!(process.env.FB_PAGE_ID && process.env.FB_PAGE_TOKEN),
      instagram: !!(process.env.IG_USER_ID && process.env.FB_PAGE_TOKEN),
      threads: !!(process.env.THREADS_USER_ID && process.env.THREADS_TOKEN),
    };
    let log = {};
    try {
      if (!getApps().length) initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}")) });
      const snap = await getFirestore().collection("socialLog").get();
      snap.forEach((d) => (log[d.id] = d.data()));
    } catch (e) {
      note = `Can't read the post log: ${esc(e.message)} (check FIREBASE_SERVICE_ACCOUNT on this project)`;
    }
    note = `Live: <b>${process.env.SOCIAL_LIVE === "true" ? "yes" : "NO (SOCIAL_LIVE not true)"}</b> · Connected: <b>${PLATFORMS.filter((p) => enabled[p]).join(", ") || "none"}</b>${note ? "<br>" + note : ""}`;
    for (const it of queue) {
      const cells = PLATFORMS.map((p) => {
        if (!it[p]) return "<td>–</td>";
        const l = log[`${it.id}_${p}`];
        if (!l) return `<td class="w">${enabled[p] ? "waiting" : "not connected"}</td>`;
        const cls = l.status === "posted" ? "ok" : l.status === "failed" ? "bad" : "w";
        return `<td class="${cls}">${esc(l.status)}${l.error ? `<br><small>${esc(l.error)}</small>` : ""}</td>`;
      }).join("");
      rows += `<tr><td>${esc(it.date.slice(5))} ${it.slot === "noon" ? "12:00" : "19:00"}</td><td>${esc(it.product)}${it.approved ? "" : " (not approved)"}</td>${cells}</tr>`;
    }
  } catch (e) {
    note = "Error: " + esc(e.message);
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Social bot status</title><style>body{font:14px -apple-system,sans-serif;margin:16px;color:#111}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}.ok{background:#e7f8ee}.bad{background:#fde8e8}.w{color:#777}small{color:#a00}</style>
<h2>Social bot status</h2><p>${note}</p><table><tr><th>When</th><th>Product</th><th>X</th><th>Threads</th><th>Instagram</th><th>Facebook</th></tr>${rows}</table>`);
};
