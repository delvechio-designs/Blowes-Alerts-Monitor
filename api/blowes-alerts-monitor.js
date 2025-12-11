// api/blowes-alerts-monitor.js
// Shopify → Vercel → Slack monitoring & anomaly detection
// Focus: card testing / fraud + important anomalies only.
// Inventory going to 0 is only logged (no Slack).
// Theme template inspector detects removed custom-liquid / big template shrink.
// John Doe + Flushing NY 11354 + yopmail abandoned checkouts get explicit fraud alerts with raw IP.

import crypto from "crypto";

// ---------- ENV CONFIG ----------

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

// Optional: Vercel KV (for durable snapshots). If not set, we fall back
// to in-memory snapshots that only live while the Lambda is warm.
const KV_URL = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;

// Admin API token for theme asset inspection (read_themes).
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const SHOPIFY_API_VERSION = "2025-01";

// Critical templates we want to watch for nuked sections (especially PDP).
const CRITICAL_THEME_TEMPLATES = [
  "templates/product.json",
  "templates/product.main.json",
  "templates/product.alternate.json",
];

// ---------- SIMPLE SNAPSHOT STORAGE ----------

// Keys look like: product:1234567890  or  theme_asset:123456:templates/product.json
const localSnapshots = new Map();

async function kvGet(key) {
  if (!KV_URL || !KV_TOKEN) {
    return localSnapshots.get(key) || null;
  }

  const res = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: {
      Authorization: `Bearer ${KV_TOKEN}`,
    },
  });

  if (!res.ok) {
    return null;
  }

  const data = await res.json().catch(() => null);
  if (!data || typeof data.value === "undefined") return null;
  try {
    return JSON.parse(data.value);
  } catch {
    return data.value;
  }
}

async function kvSet(key, value) {
  if (!KV_URL || !KV_TOKEN) {
    localSnapshots.set(key, value);
    return;
  }

  await fetch(`${KV_URL}/set/${encodeURIComponent(key)}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${KV_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ value: JSON.stringify(value) }),
  }).catch(() => {});
}

async function loadSnapshot(type, id) {
  const key = `${type}:${id}`;
  return kvGet(key);
}

async function saveSnapshot(type, id, data) {
  const key = `${type}:${id}`;
  return kvSet(key, data);
}

// ---------- GENERAL HELPERS ----------

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function truncate(str, max = 600) {
  if (!str) return "";
  if (str.length <= max) return str;
  return str.slice(0, max) + "\n…(truncated)…";
}

async function sendSlackMessage(blocks) {
  if (!SLACK_WEBHOOK_URL) return;
  await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ blocks }),
  }).catch(() => {});
}

function buildSlackHeader(text, emoji = "🧾") {
  return {
    type: "section",
    text: {
      type: "mrkdwn",
      text: `${emoji} *${text}*`,
    },
  };
}

function buildSlackDivider() {
  return { type: "divider" };
}

function buildField(label, value) {
  return {
    type: "mrkdwn",
    text: `*${label}:*\n${value}`,
  };
}

// ---------- ANOMALY STATE (in-memory windows) ----------

const recentCheckouts = []; // { timestamp, emailHash, amount, ip, nameHash, lineHash }
const RECENT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function hashValue(value) {
  if (!value) return "unknown";
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function maskIp(ip) {
  if (!ip) return "unknown";
  const hash = hashValue(ip).slice(0, 10);
  return `ip#${hash}`;
}

function nowMs() {
  return Date.now();
}

function pruneRecentCheckouts() {
  const cutoff = nowMs() - RECENT_WINDOW_MS;
  while (recentCheckouts.length && recentCheckouts[0].timestamp < cutoff) {
    recentCheckouts.shift();
  }
}

// ---------- DIFF HELPERS ----------

function diffObjects(before, after) {
  if (!before || !after) return null;

  const changes = {};
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);

  for (const key of keys) {
    const b = before[key];
    const a = after[key];

    // ignore timestamps & obviously noisy keys
    if (
      key === "updated_at" ||
      key === "created_at" ||
      key === "published_at"
    ) {
      continue;
    }

    const bStr = safeJson(b);
    const aStr = safeJson(a);
    if (bStr !== aStr) {
      changes[key] = { before, after };
      changes[key] = { before: b, after: a };
    }
  }

  return Object.keys(changes).length ? changes : null;
}

function formatChangesForSlack(changes) {
  if (!changes) return "No diff available.";

  const lines = [];
  for (const [key, value] of Object.entries(changes)) {
    lines.push(
      `• *${key}:*\n  • Before:\n\`\`\`${truncate(
        safeJson(value.before),
        400
      )}\`\`\`\n  • After:\n\`\`\`${truncate(safeJson(value.after), 400)}\`\`\``
    );
  }
  return lines.join("\n");
}

// ---------- ANOMALY DETECTORS ----------

// 1) Card testing / checkout surge (generic)
function detectCheckoutAnomaly(newEntry) {
  pruneRecentCheckouts();
  recentCheckouts.push(newEntry);

  const windowEntries = recentCheckouts.filter(
    (c) => nowMs() - c.timestamp <= RECENT_WINDOW_MS
  );

  const totalInWindow = windowEntries.length;

  const GLOBAL_THRESHOLD = 10; // 10+ checkouts in 15 min
  const GLOBAL_BURST_THRESHOLD = 5; // 5+ checkouts in 3 min
  const shortWindowMs = 3 * 60 * 1000;
  const shortEntries = windowEntries.filter(
    (c) => nowMs() - c.timestamp <= shortWindowMs
  );

  let reason = null;

  if (shortEntries.length >= GLOBAL_BURST_THRESHOLD) {
    reason = `High volume: ${shortEntries.length} checkouts in last 3 minutes (${totalInWindow} in 15 minutes).`;
  } else if (totalInWindow >= GLOBAL_THRESHOLD) {
    reason = `Sustained volume: ${totalInWindow} checkouts in last 15 minutes.`;
  }

  // Cluster by IP
  const ipMap = {};
  for (const e of windowEntries) {
    if (!e.ip) continue;
    ipMap[e.ip] = (ipMap[e.ip] || 0) + 1;
  }

  let highestIp = null;
  let highestIpCount = 0;
  for (const [ip, count] of Object.entries(ipMap)) {
    if (count > highestIpCount) {
      highestIpCount = count;
      highestIp = ip;
    }
  }

  if (highestIp && highestIpCount >= 5) {
    reason = reason
      ? `${reason} Clustered by IP: ${highestIpCount} from same IP.`
      : `Clustered by IP: ${highestIpCount} checkouts from one IP in 15 minutes.`;
  }

  // Cluster by amount
  const amountMap = {};
  for (const e of windowEntries) {
    if (typeof e.amount !== "number") continue;
    const key = e.amount.toFixed(2);
    amountMap[key] = (amountMap[key] || 0) + 1;
  }

  let domAmount = null;
  let domAmountCount = 0;
  for (const [amt, count] of Object.entries(amountMap)) {
    if (count > domAmountCount) {
      domAmountCount = count;
      domAmount = amt;
    }
  }

  if (domAmount && domAmountCount >= 5) {
    reason = reason
      ? `${reason} Repeated amount $${domAmount} (${domAmountCount} times).`
      : `Repeated cart amount $${domAmount} (${domAmountCount} checkouts).`;
  }

  if (!reason) return null;

  return {
    reason,
    totalInWindow,
    ipCluster: highestIp ? { ip: highestIp, count: highestIpCount } : null,
    domAmount: domAmount ? { amount: domAmount, count: domAmountCount } : null,
  };
}

// 2) Big price spikes / drops
function detectPriceAnomaly(before, after) {
  if (!before || !after || !Array.isArray(before.variants)) return null;

  const changes = [];
  const beforeMap = {};
  before.variants.forEach((v) => {
    if (v.id) beforeMap[v.id] = v;
  });

  for (const vAfter of after.variants || []) {
    const vBefore = beforeMap[vAfter.id];
    if (!vBefore) continue;
    const oldPrice = parseFloat(vBefore.price);
    const newPrice = parseFloat(vAfter.price);
    if (!isFinite(oldPrice) || !isFinite(newPrice) || oldPrice === 0) continue;

    const delta = newPrice - oldPrice;
    const pct = (delta / oldPrice) * 100;
    if (Math.abs(pct) >= 50) {
      changes.push({
        variantId: vAfter.id,
        oldPrice,
        newPrice,
        pct,
        title: vAfter.title || vAfter.sku || "Variant",
      });
    }
  }

  return changes.length ? changes : null;
}

// 3) Inventory anomalies (big jumps only)
function detectInventoryAnomaly(before, after) {
  if (!before || !after || !Array.isArray(before.variants)) return null;

  const issues = [];
  const beforeMap = {};
  before.variants.forEach((v) => {
    if (v.id) beforeMap[v.id] = v;
  });

  for (const vAfter of after.variants || []) {
    const vBefore = beforeMap[vAfter.id];
    if (!vBefore) continue;
    const oldQty = vBefore.inventory_quantity ?? null;
    const newQty = vAfter.inventory_quantity ?? null;

    if (oldQty == null || newQty == null) continue;
    const delta = newQty - oldQty;

    // Zero stock is logged via snapshot, but not treated as a Slack anomaly.
    if (oldQty > 0 && newQty === 0) {
      continue;
    }

    if (Math.abs(delta) >= 100) {
      issues.push({
        variantId: vAfter.id,
        type: "big_jump",
        oldQty,
        newQty,
        delta,
      });
    }
  }

  return issues.length ? issues : null;
}

// 4) High-risk discounts
function detectDiscountAnomaly(discount) {
  if (!discount) return null;

  const anomalies = [];

  const percentage = discount.value
    ? parseFloat(discount.value)
    : discount.value_type === "percentage"
    ? parseFloat(discount.value)
    : null;

  if (percentage && percentage >= 60) {
    anomalies.push(`High percentage discount: ${percentage}%`);
  }

  if (discount.usage_limit && discount.usage_limit < 0) {
    anomalies.push("Negative or invalid usage limit.");
  }

  if (discount.starts_at && !discount.ends_at) {
    anomalies.push("No end date set for discount.");
  }

  return anomalies.length ? anomalies : null;
}

// ---------- THEME TEMPLATE INSPECTION ----------

async function fetchThemeAssetValue(shopDomain, themeId, assetKey) {
  if (!SHOPIFY_ADMIN_TOKEN) return null;

  const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/themes/${themeId}/assets.json?asset[key]=${encodeURIComponent(
    assetKey
  )}`;

  const res = await fetch(url, {
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    console.warn("Failed to fetch theme asset", {
      shopDomain,
      themeId,
      assetKey,
      status: res.status,
    });
    return null;
  }

  const json = await res.json().catch(() => null);
  if (!json || !json.asset || typeof json.asset.value !== "string") {
    return null;
  }

  return json.asset.value;
}

function detectThemeTemplateRemoval(prevStr, currStr) {
  if (!prevStr || !currStr) return null;

  const prevLen = prevStr.length;
  const currLen = currStr.length;
  const notes = [];

  if (prevLen && currLen < prevLen * 0.8) {
    notes.push(
      `Template content shrank from ${prevLen} chars to ${currLen} chars.`
    );
  }

  const prevHasCustom = prevStr.includes("custom-liquid");
  const currHasCustom = currStr.includes("custom-liquid");

  if (prevHasCustom && !currHasCustom) {
    notes.push("custom-liquid section reference was removed from this template.");
  }

  return notes.length ? { prevLen, currLen, notes } : null;
}

async function inspectThemeTemplates(themePayload, context) {
  if (!SHOPIFY_ADMIN_TOKEN) return [];

  const shopDomain = context.shopDomain;
  const themeId = themePayload.id;
  const results = [];

  for (const assetKey of CRITICAL_THEME_TEMPLATES) {
    const currentValue = await fetchThemeAssetValue(
      shopDomain,
      themeId,
      assetKey
    );
    if (!currentValue) continue;

    const snapshotId = `${themeId}:${assetKey}`;
    const previousSnapshot = await loadSnapshot("theme_asset", snapshotId);
    await saveSnapshot("theme_asset", snapshotId, { value: currentValue });

    if (previousSnapshot && typeof previousSnapshot.value === "string") {
      const anomaly = detectThemeTemplateRemoval(
        previousSnapshot.value,
        currentValue
      );
      if (anomaly) {
        results.push({
          assetKey,
          prevLen: anomaly.prevLen,
          currLen: anomaly.currLen,
          notes: anomaly.notes,
        });
      }
    }
  }

  return results;
}

function isImportantThemeEvent(themePayload) {
  return !!themePayload;
}

// ---------- SUSPICIOUS IDENTITY / JOHN DOE CHECK ----------

function isDisposableEmail(email) {
  if (!email) return false;
  const lower = email.toLowerCase();
  // You can add more disposable providers here if you want.
  return lower.includes("@yopmail.");
}

function detectSuspiciousCheckoutIdentity(payload, browserIp) {
  const billing = payload.billing_address || {};
  const shipping = payload.shipping_address || {};
  const customer = payload.customer || {};

  const first =
    billing.first_name ||
    shipping.first_name ||
    customer.first_name ||
    "";
  const last =
    billing.last_name ||
    shipping.last_name ||
    customer.last_name ||
    "";
  const fullName = `${first} ${last}`.trim().toLowerCase();

  const city = (billing.city || shipping.city || "").toLowerCase();
  const zip = (billing.zip || shipping.zip || "").trim();
  const country = (billing.country || shipping.country || "").toLowerCase();
  const province = (billing.province || shipping.province || "").toLowerCase();
  const provinceCode = (
    billing.province_code ||
    shipping.province_code ||
    ""
  ).toLowerCase();

  const email = payload.email || customer.email || null;

  const isJohnDoe = fullName === "john doe";
  const isFlushing = city === "flushing" && zip === "11354";
  const isUS =
    country === "united states" ||
    country === "united states of america" ||
    country === "usa" ||
    country === "us";
  const isNY = province === "new york" || provinceCode === "ny";

  const hasYopmail = isDisposableEmail(email);

  const reasons = [];

  if (isJohnDoe && isFlushing && isUS && isNY) {
    reasons.push("Exact John Doe + Flushing NY 11354 US pattern");
  }
  if (hasYopmail) {
    reasons.push("Disposable email domain (yopmail)");
  }

  // You can expand this later if you want to catch
  // "John Doe" anywhere in US, or other cities.
  if (!reasons.length) return null;

  return {
    email,
    firstName: first,
    lastName: last,
    fullName,
    city,
    zip,
    country,
    province,
    provinceCode,
    browserIp: browserIp || null,
    reasons,
  };
}

// ---------- HANDLERS FOR TOPICS ----------

// Products
async function handleProductUpdate(payload, context) {
  const productId = payload.id;
  const type = "product";

  const previous = await loadSnapshot(type, productId);
  await saveSnapshot(type, productId, payload);

  if (!previous) {
    return;
  }

  const priceAnoms = detectPriceAnomaly(previous, payload);
  const invAnoms = detectInventoryAnomaly(previous, payload);

  if (!priceAnoms && !invAnoms) return;

  const fields = [];

  if (priceAnoms && priceAnoms.length) {
    const lines = priceAnoms.map(
      (p) =>
        `• ${p.title}: ${p.oldPrice} → ${p.newPrice} (${p.pct.toFixed(1)}%)`
    );
    fields.push(buildField("Price changes", lines.join("\n")));
  }

  if (invAnoms && invAnoms.length) {
    const lines = invAnoms.map((i) => {
      return `• Variant ${i.variantId}: inventory ${i.oldQty} → ${i.newQty} (Δ ${i.delta})`;
    });
    fields.push(buildField("Inventory anomalies", lines.join("\n")));
  }

  const blocks = [
    buildSlackHeader(
      `[ANOMALY][PRODUCT] ${payload.title || "(no title)"}`
    ),
    {
      type: "section",
      fields: [
        buildField("Category", "PRODUCT"),
        buildField("Topic", context.topic),
        buildField("Shop", context.shopDomain),
        buildField("Resource ID", String(productId)),
      ],
    },
    buildSlackDivider(),
    {
      type: "section",
      fields,
    },
  ];

  await sendSlackMessage(blocks);
}

// Discounts
async function handleDiscountUpdate(payload, context) {
  const discountId = payload.id || payload.discount_id;
  const type = "discount";

  const previous = await loadSnapshot(type, discountId);
  await saveSnapshot(type, discountId, payload);

  const anomalies = detectDiscountAnomaly(payload);
  if (!anomalies || !anomalies.length) return;

  const blocks = [
    buildSlackHeader(
      `[ANOMALY][DISCOUNT] ${payload.title || payload.code || "Discount"}`
    ),
    {
      type: "section",
      fields: [
        buildField("Category", "DISCOUNT"),
        buildField("Topic", context.topic),
        buildField("Shop", context.shopDomain),
        buildField("Resource ID", String(discountId)),
      ],
    },
    buildSlackDivider(),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: anomalies.map((a) => `• ${a}`).join("\n"),
      },
    },
  ];

  await sendSlackMessage(blocks);
}

// Themes
async function handleThemeEvent(payload, context) {
  if (!isImportantThemeEvent(payload)) return;

  const templateAnomalies = await inspectThemeTemplates(payload, context);

  const blocks = [
    buildSlackHeader(
      `[THEME][${context.topic.toUpperCase()}] ${payload.name || "Theme"}`
    ),
    {
      type: "section",
      fields: [
        buildField("Category", "THEME"),
        buildField("Topic", context.topic),
        buildField("Shop", context.shopDomain),
        buildField("Theme ID", String(payload.id)),
        buildField("Role", payload.role || "unknown"),
      ],
    },
  ];

  if (templateAnomalies && templateAnomalies.length) {
    const lines = templateAnomalies.map((a) => {
      const notes = a.notes.map((n) => `  • ${n}`).join("\n");
      return `• *${a.assetKey}*\n${notes}`;
    });

    blocks.push(buildSlackDivider());
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          "*Template anomalies detected (possible removed sections / nuked PDP content):*\n" +
          lines.join("\n\n"),
      },
    });
  }

  await sendSlackMessage(blocks);
}

// Checkouts: fraud & John Doe detection
async function handleCheckoutUpdate(payload, context) {
  // Only care about incomplete / abandoned-type ones here
  if (payload.completed_at) {
    return;
  }

  const browserIp =
    payload.client_details?.browser_ip ||
    payload.customer?.last_order_ip ||
    null;

  const email = payload.email || payload.customer?.email || null;
  const amount = payload.total_price
    ? parseFloat(payload.total_price)
    : payload.subtotal_price
    ? parseFloat(payload.subtotal_price)
    : null;
  const name =
    payload.customer?.first_name ||
    payload.billing_address?.first_name ||
    "unknown";

  const emailHash = email ? hashValue(email) : "unknown";
  const nameHash = name ? hashValue(name) : "unknown";

  const lineHash = hashValue(
    (payload.line_items || [])
      .map((li) => `${li.sku || li.title}:${li.quantity}`)
      .join("|")
  );

  const entry = {
    timestamp: nowMs(),
    emailHash,
    amount: typeof amount === "number" ? amount : null,
    ip: browserIp || null,
    nameHash,
    lineHash,
  };

  // 1) Specific John Doe / Yopmail / Flushing NY pattern detection
  const suspiciousIdentity = detectSuspiciousCheckoutIdentity(
    payload,
    browserIp
  );
  if (suspiciousIdentity) {
    const {
      email: suspEmail,
      firstName,
      lastName,
      city,
      zip,
      country,
      province,
      provinceCode,
      browserIp: suspIp,
      reasons,
    } = suspiciousIdentity;

    const addrSummary = `${city || "(no city)"}, ${province || provinceCode || "(no state)"} ${zip || ""}, ${country || "(no country)"}`.trim();

    const blocks = [
      buildSlackHeader("[FRAUD][SUSPECT ABANDONED CHECKOUT – JOHN DOE PATTERN]", "🚨"),
      {
        type: "section",
        fields: [
          buildField("Category", "CHECKOUT / FRAUD"),
          buildField("Topic", context.topic),
          buildField("Shop", context.shopDomain),
        ],
      },
      buildSlackDivider(),
      {
        type: "section",
        fields: [
          buildField(
            "Name",
            `${firstName || ""} ${lastName || ""}`.trim() || "(unknown)"
          ),
          buildField("Email", suspEmail || "(none)"),
        ],
      },
      {
        type: "section",
        fields: [
          buildField("IP (raw)", suspIp || "(none)"),
          buildField("Address (summary)", addrSummary || "(none)"),
        ],
      },
      buildSlackDivider(),
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text:
            "*Detection reasons:*\n" +
            reasons.map((r) => `• ${r}`).join("\n"),
        },
      },
      buildSlackDivider(),
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text:
            "_This alert intentionally includes PII (IP, email, name, address) for fraud investigation of a known bad pattern (John Doe / disposable email abandoned carts)._",
        },
      },
    ];

    await sendSlackMessage(blocks);
  }

  // 2) Generic card-testing / surge anomaly (still hashed PII)
  const anomaly = detectCheckoutAnomaly(entry);
  if (!anomaly) return;

  const maskedIp = anomaly.ipCluster ? maskIp(anomaly.ipCluster.ip) : "unknown";

  const blocks = [
    buildSlackHeader("[ANOMALY][CARD TESTING SUSPECTED]"),
    {
      type: "section",
      fields: [
        buildField("Category", "CHECKOUT / FRAUD"),
        buildField("Topic", context.topic),
        buildField("Shop", context.shopDomain),
      ],
    },
    buildSlackDivider(),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          `*Reason:*\n${anomaly.reason}\n\n` +
          `*Approx Stats (last 15min)*\n` +
          `• Total checkouts: ${anomaly.totalInWindow}\n` +
          (anomaly.domAmount
            ? `• Dominant amount: $${anomaly.domAmount.amount} (${anomaly.domAmount.count} checkouts)\n`
            : "") +
          (anomaly.ipCluster
            ? `• IP cluster: ${maskedIp} (${anomaly.ipCluster.count} checkouts)\n`
            : ""),
      },
    },
    buildSlackDivider(),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          "*Privacy Note:*\n" +
          "For generic anomalies, email, name and IP are *hashed* internally for grouping. " +
          "Use this alert as a signal to inspect Abandoned Checkouts in Shopify directly.",
      },
    },
  ];

  await sendSlackMessage(blocks);
}

// Content (pages, collections, articles)
async function handleContentUpdate(payload, context, typeLabel, idField = "id") {
  const resourceId = payload[idField];
  const type = typeLabel.toLowerCase();

  const previous = await loadSnapshot(type, resourceId);
  await saveSnapshot(type, resourceId, payload);

  if (!previous) return;

  const changes = diffObjects(previous, payload);
  if (!changes) return;

  const beforeBody =
    previous.body_html || previous.body || previous.content || "";
  const afterBody = payload.body_html || payload.body || payload.content || "";

  const beforeLen = (beforeBody || "").length;
  const afterLen = (afterBody || "").length;

  let isBigChange = false;
  if (beforeLen && afterLen < beforeLen * 0.2) {
    isBigChange = true;
  }

  if (!isBigChange) return;

  const blocks = [
    buildSlackHeader(`[ANOMALY][${typeLabel.toUpperCase()} CONTENT CHANGE]`),
    {
      type: "section",
      fields: [
        buildField("Category", typeLabel.toUpperCase()),
        buildField("Topic", context.topic),
        buildField("Shop", context.shopDomain),
        buildField("Resource ID", String(resourceId)),
        buildField(
          "Body length",
          `Before: ${beforeLen} chars\nAfter: ${afterLen} chars`
        ),
      ],
    },
    buildSlackDivider(),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          "*Detected a large reduction in content. This may hurt SEO or break page layout.*",
      },
    },
    buildSlackDivider(),
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: "*Sample diff:*\n" + formatChangesForSlack(changes),
      },
    },
  ];

  await sendSlackMessage(blocks);
}

// ---------- MAIN HANDLER ----------

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).send("Method not allowed");
    return;
  }

  if (!SHOPIFY_WEBHOOK_SECRET) {
    res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");
    return;
  }

  const rawBody = await new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });

  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const topic = req.headers["x-shopify-topic"];
  const shopDomain = req.headers["x-shopify-shop-domain"];

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  if (
    !hmacHeader ||
    !crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader))
  ) {
    console.warn("Invalid HMAC for webhook", { shopDomain, topic });
    res.status(401).send("Invalid HMAC");
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch (err) {
    console.error("Failed to parse webhook JSON", err);
    res.status(400).send("Invalid JSON");
    return;
  }

  const context = { shopDomain, topic };

  try {
    switch (topic) {
      case "products/update":
        await handleProductUpdate(payload, context);
        break;

      case "discounts/create":
      case "discounts/update":
        await handleDiscountUpdate(payload, context);
        break;

      case "themes/update":
      case "themes/publish":
        await handleThemeEvent(payload, context);
        break;

      case "checkouts/update":
        await handleCheckoutUpdate(payload, context);
        break;

      case "pages/update":
        await handleContentUpdate(payload, context, "page");
        break;

      case "collections/update":
        await handleContentUpdate(payload, context, "collection");
        break;

      case "articles/update":
        await handleContentUpdate(payload, context, "article", "id");
        break;

      default:
        // Unhandled topics: snapshots/logging only if you wire it up separately.
        break;
    }
  } catch (err) {
    console.error("Error handling webhook topic", topic, err);
  }

  res.status(200).send("OK");
}
