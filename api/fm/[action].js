// FaceMosaic licensing on top of Stripe — no separate database.
//
// A sale is a Stripe Checkout Session (from a Payment Link). Its PaymentIntent holds the license:
//   key            FM-<payment intent id without "pi_">-<10-char HMAC>   (can't be guessed or forged)
//   metadata       fm_product=facemosaic, fm_key=<key>, fm_machines=<id,id>  (activated Macs)
// Refunded or disputed payments stop validating automatically.
//
// Endpoints (all under /api/fm/):
//   GET  claim?session_id=cs_...                         → { key }   (thank-you page, after paying)
//   POST activate   license_key, instance_name, machine, nonce
//   POST validate   license_key, instance_id, nonce
//   POST deactivate license_key, instance_id, nonce
// activate/validate/deactivate answer in the shape the FaceMosaic engine expects and are signed
// (sig = HMAC(FM_RESPONSE_SECRET, nonce|action|ok|key)) so a fake server can't unlock the app.
//
// Vercel environment variables:
//   STRIPE_SECRET_KEY    restricted key: Checkout Sessions read, PaymentIntents read+write
//   FM_PRICE_ID          the Stripe price id of FaceMosaic (only purchases of this price get a key)
//   FM_LICENSE_SECRET    random string (makes keys unforgeable) — never change it after launch
//   FM_RESPONSE_SECRET   random string, also stamped into the release build
//   FM_MAX_MACS          optional, default 2

const crypto = require("crypto");

const STRIPE = "https://api.stripe.com/v1";
const MAX_MACS = parseInt(process.env.FM_MAX_MACS || "2", 10);

async function stripe(path, { method = "GET", form } = {}) {
  const r = await fetch(STRIPE + path, {
    method,
    headers: {
      Authorization: "Bearer " + process.env.STRIPE_SECRET_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form ? new URLSearchParams(form).toString() : undefined,
  });
  const j = await r.json();
  if (!r.ok) {
    const e = new Error((j.error && j.error.message) || "stripe error");
    e.status = r.status;
    throw e;
  }
  return j;
}

function hmac(secret, text) {
  return crypto.createHmac("sha256", secret).update(text).digest("hex");
}

function makeKey(piId) {
  const tag = hmac(process.env.FM_LICENSE_SECRET, "fm-key:" + piId).slice(0, 10).toUpperCase();
  return `FM-${piId.slice(3)}-${tag}`;
}

// key -> payment intent id, or null if the key is malformed or forged
function keyToPi(key) {
  const m = /^FM-([A-Za-z0-9]+)-([0-9A-F]{10})$/.exec(String(key || "").trim());
  if (!m) return null;
  const pi = "pi_" + m[1];
  const want = makeKey(pi);
  const a = Buffer.from(want), b = Buffer.from(String(key).trim());
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? pi : null;
}

function machinesOf(pi) {
  return ((pi.metadata && pi.metadata.fm_machines) || "").split(",").filter(Boolean);
}

// Is this PaymentIntent a paid, un-refunded, un-disputed FaceMosaic purchase?
function licenseStatus(pi) {
  if (!pi || pi.metadata?.fm_product !== "facemosaic") return "invalid";
  if (pi.status !== "succeeded") return "invalid";
  const ch = pi.latest_charge;
  if (ch && typeof ch === "object" && (ch.refunded || ch.amount_refunded > 0 || ch.disputed)) return "disabled";
  return "active";
}

function sign(nonce, action, ok, key) {
  const secret = process.env.FM_RESPONSE_SECRET || "";
  return secret ? hmac(secret, `${nonce}|${action}|${ok ? 1 : 0}|${key}`) : "";
}

async function loadPi(key) {
  const piId = keyToPi(key);
  if (!piId) return null;
  try {
    return await stripe(`/payment_intents/${piId}?expand[]=latest_charge`);
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

async function claim(req, res) {
  const sid = String(req.query.session_id || "");
  if (!/^cs_[A-Za-z0-9_]+$/.test(sid)) return res.status(400).json({ error: "missing session" });
  const s = await stripe(`/checkout/sessions/${sid}?expand[]=line_items&expand[]=payment_intent`);
  if (s.payment_status !== "paid" || !s.payment_intent) return res.status(402).json({ error: "not paid yet" });
  const items = (s.line_items && s.line_items.data) || [];
  if (!items.some((li) => li.price && li.price.id === process.env.FM_PRICE_ID)) {
    return res.status(404).json({ error: "this purchase doesn't include FaceMosaic" });
  }
  const pi = s.payment_intent;
  const key = makeKey(pi.id);           // deterministic: reloading the page shows the same key
  if (pi.metadata?.fm_key !== key) {
    await stripe(`/payment_intents/${pi.id}`, {
      method: "POST",
      form: {
        "metadata[fm_product]": "facemosaic",
        "metadata[fm_key]": key,
        "metadata[fm_machines]": pi.metadata?.fm_machines || "",
        description: `FaceMosaic license ${key}`,
      },
    });
  }
  res.setHeader("Cache-Control", "no-store");
  return res.json({ key, email: (s.customer_details && s.customer_details.email) || "", max_macs: MAX_MACS });
}

async function licenseAction(action, req, res) {
  const b = req.body || {};
  const key = String(b.license_key || "").trim();
  const nonce = String(b.nonce || "");
  const reply = (ok, body) => res.json({ ...body, sig: sign(nonce, action, ok, key) });

  const pi = await loadPi(key);
  const status = licenseStatus(pi);
  if (status === "invalid") {
    return reply(false, { [action === "activate" ? "activated" : action === "validate" ? "valid" : "deactivated"]: false,
                          error: "license key not found" });
  }
  const machines = machinesOf(pi);
  const info = { status, activation_usage: machines.length, activation_limit: MAX_MACS };

  if (action === "validate") {
    const id = String(b.instance_id || "");
    const ok = status === "active" && machines.includes(id);
    return reply(ok, { valid: ok, license_key: info, error: ok ? null : status === "active" ? "not activated on this Mac" : "license " + status });
  }

  if (action === "deactivate") {
    const id = String(b.instance_id || "");
    const rest = machines.filter((m) => m !== id);
    if (rest.length !== machines.length) {
      await stripe(`/payment_intents/${pi.id}`, { method: "POST", form: { "metadata[fm_machines]": rest.join(",") } });
    }
    return reply(true, { deactivated: true, license_key: { ...info, activation_usage: rest.length } });
  }

  // activate
  if (status !== "active") return reply(false, { activated: false, error: "license " + status });
  const id = String(b.machine || "").replace(/[^a-f0-9]/g, "").slice(0, 16);
  if (id.length !== 16) return reply(false, { activated: false, error: "bad machine id" });
  if (!machines.includes(id)) {
    if (machines.length >= MAX_MACS) return reply(false, { activated: false, error: "activation limit reached", license_key: info });
    machines.push(id);
    await stripe(`/payment_intents/${pi.id}`, { method: "POST", form: { "metadata[fm_machines]": machines.join(",") } });
  }
  return reply(true, { activated: true, instance: { id }, license_key: { ...info, activation_usage: machines.length } });
}

module.exports = async (req, res) => {
  const action = req.query.action;
  try {
    if (!process.env.STRIPE_SECRET_KEY || !process.env.FM_LICENSE_SECRET) {
      return res.status(503).json({ error: "licensing not configured" });
    }
    if (action === "claim" && req.method === "GET") return await claim(req, res);
    if (["activate", "validate", "deactivate"].includes(action) && req.method === "POST") {
      return await licenseAction(action, req, res);
    }
    return res.status(404).json({ error: "not found" });
  } catch (e) {
    console.error("fm", action, e.message);
    return res.status(502).json({ error: "license server problem, try again shortly" });
  }
};
