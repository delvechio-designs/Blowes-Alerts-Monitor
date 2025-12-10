// api/blowes-alerts-monitor.js
// Shopify monitor that:
// - Tracks ALL webhooks and stores full snapshots (including PII) in memory
// - Only sends Slack alerts for anomalies / critical events:
//     * Suspected card testing / abusive checkout patterns (orders/checkouts)
//     * app/uninstalled
//     * themes/publish
// - Masks PII in Slack messages

const crypto = require("crypto");

// === CONFIG (from Vercel env vars) ===
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || null;

// === In-memory stores (can be swapped to KV later) ===

// Full snapshots keyed by shop + resource id
const snapshotStore = new Map();

// Simple rolling fraud tracker keyed by email/ip/cart_token
// value: array of timestamps (ms) of suspicious-ish events
const fraudTracker = new Map();

// Topics with significant PII in payloads
const PII_TOPICS = new Set([
  "orders/create",
  "orders/updated",
  "orders/paid",
  "orders/cancelled",
  "checkouts/create",
  "checkouts/update",
  "customers/create",
  "customers/update",
]);

// Critical, non-fraud events we ALWAYS want to see
const CRITICAL_TOPICS = new Set([
  "app/uninstalled",
  "themes/publish",
]);

// === SNAPSHOT HELPERS ===

async function getSnapshot(key) {
  return snapshotStore.get(key) || null;
}

async function setSnapshot(key, snapshot) {
  snapshotStore.set(key, snapshot);
}

// === BASIC HELPERS ===

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function isValidShopifyHmac(rawBody, hmacHeader) {
  if (!hmacHeader || !SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  const sigBuf = Buffer.from(digest, "utf8");
  const hdrBuf = Buffer.from(hmacHeader, "utf8");

  if (sigBuf.length !== hdrBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, hdrBuf);
}

function parseTopic(topic) {
  if (!topic) return { resourceType: "unknown", action: "unknown" };
  const [resourceType, action] = topic.split("/");
  return { resourceType, action };
}

function getResourceId(resourceType, payload) {
  if (!payload || typeof payload !== "object") return null;
  return payload.id || payload.admin_graphql_api_id || null;
}

function buildSnapshotKey(resourceType, resourceId, shopDomain) {
  return `${shopDomain || "shop"}/${resourceType}/${resourceId || "unknown"}`;
}

function summarize(value) {
  if (value === null || value === undefined) return String(value);

  if (typeof value === "string") {
    const t = value.trim();
    if (t.length > 240) return `${t.slice(0, 180)} … ${t.slice(-40)}`;
    return t;
  }

  if (Array.isArray(value)) {
    try {
      const json = JSON.stringify(value, null, 2);
      const limit = 1500;
      return json.length > limit ? json.slice(0, limit) + "\n… (truncated)" : json;
    } catch {
      return `[Array(${value.length})]`;
    }
  }

  if (typeof value === "object") {
    try {
      const json = JSON.stringify(value, null, 2);
      if (json.length > 1500) return json.slice(0, 1500) + "\n… (truncated)";
      return json;
    } catch {
      return "[Object]";
    }
  }

  return String(value);
}

// === PII MASKING ===

const PII_KEYS = new Set([
  "email",
  "phone",
  "first_name",
  "last_name",
  "name",
  "address1",
  "address2",
  "city",
  "province",
  "zip",
  "postal_code",
  "country",
  "company",
]);

function maskEmail(email) {
  if (!email || typeof email !== "string" || !email.includes("@")) return email;
  const [user, domain] = email.split("@");
  if (user.length <= 2) return `*${"*".repeat(user.length)}@${domain}`;
  return `${user[0]}***${user[user.length - 1]}@${domain}`;
}

function stripPII(obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(stripPII);

  const result = {};
  for (const [key, val] of Object.entries(obj)) {
    if (PII_KEYS.has(key)) {
      if (key === "email") {
        result[key] = maskEmail(val);
      } else {
        result[key] = "[redacted]";
      }
    } else if (val && typeof val === "object") {
      result[key] = stripPII(val);
    } else {
      result[key] = val;
    }
  }
  return result;
}

// === DIFF LOGIC (still used for critical events if you want it later) ===

function diffObjects(before, after, pathPrefix = "", changes = [], depth = 0) {
  if (depth > 4) return changes;
  if (before === undefined && after === undefined) return changes;

  if (
    typeof before !== "object" ||
    before === null ||
    typeof after !== "object" ||
    after === null
  ) {
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({
        path: pathPrefix || "(root)",
        before,
        after,
      });
    }
    return changes;
  }

  if (Array.isArray(before) || Array.isArray(after)) {
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({
        path: pathPrefix || "(array)",
        beforeSummary: summarize(before),
        afterSummary: summarize(after),
      });
    }
    return changes;
  }

  const keys = new Set([
    ...Object.keys(before || {}),
    ...Object.keys(after || {}),
  ]);

  for (const key of keys) {
    if (["created_at", "updated_at", "admin_graphql_api_id"].includes(key)) {
      continue;
    }
    const nextPath = pathPrefix ? `${pathPrefix}.${key}` : key;
    diffObjects(
      before ? before[key] : undefined,
      after ? after[key] : undefined,
      nextPath,
      changes,
      depth + 1
    );
  }

  return changes;
}

// === FRAUD / CARD-TESTING HEURISTIC ===

function getFraudIdentifier(topic, payload) {
  const email =
    payload.email ||
    payload.customer?.email ||
    payload.billing_address?.email ||
    payload.shipping_address?.email;

  const ip =
    payload.client_details?.browser_ip ||
    payload.client_details?.ip_address ||
    null;

  const cartToken = payload.cart_token || payload.token || null;

  if (email && ip) return `email:${email}|ip:${ip}`;
  if (email) return `email:${email}`;
  if (ip) return `ip:${ip}`;
  if (cartToken) return `cart:${cartToken}`;
  return null;
}

function recordFraudEvent(identifier) {
  if (!identifier) return 0;
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; // 10 minutes

  const existing = fraudTracker.get(identifier) || [];
  const filtered = existing.filter((t) => now - t < windowMs);
  filtered.push(now);
  fraudTracker.set(identifier, filtered);
  return filtered.length;
}

function isSuspiciousOrderOrCheckout(topic, payload) {
  const identifier = getFraudIdentifier(topic, payload);
  const count = recordFraudEvent(identifier);

  if (!identifier) return false;

  // Simple heuristic:
  // - orders: lots of voided/refunded/cancelled in short window
  // - checkouts: many abandoned/recovery statuses in short window
  if (topic.startsWith("orders/")) {
    const financialStatus = (payload.financial_status || "").toLowerCase();
    const cancelledAt = payload.cancelled_at || null;
    if (
      ["voided", "refunded"].includes(financialStatus) ||
      cancelledAt
    ) {
      if (count >= 3) return true;
    }
  }

  if (topic.startsWith("checkouts/")) {
    const status = (payload.status || "").toLowerCase();
    if (["abandoned", "recovery"].includes(status)) {
      if (count >= 3) return true;
    }
  }

  return false;
}

// === SLACK HELPERS ===

async function sendSlack(payload) {
  if (!SLACK_WEBHOOK_URL) return;
  await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function buildFraudSlackPayload(topic, resourceType, resourceId, shopDomain, payload) {
  const email =
    payload.email ||
    payload.customer?.email ||
    payload.billing_address?.email ||
    payload.shipping_address?.email;

  const ip =
    payload.client_details?.browser_ip ||
    payload.client_details?.ip_address ||
    "Unknown";

  const maskedEmail = maskEmail(email);

  const resourceName =
    payload.name ||
    payload.order_number ||
    payload.cart_token ||
    String(resourceId);

  const title = `[FRAUD][POSSIBLE CARD TESTING] ${resourceName}`;

  const details = [
    `• Topic: \`${topic}\``,
    `• Masked Email: \`${maskedEmail || "Unknown"}\``,
    `• IP: \`${ip}\``,
    `• Total Price: ${
      payload.total_price ||
      payload.total_price_set?.shop_money?.amount ||
      "Unknown"
    }`,
    `• Gateway: ${
      payload.gateway ||
      (Array.isArray(payload.payment_gateway_names)
        ? payload.payment_gateway_names.join(", ")
        : "Unknown")
    }`,
  ].join("\n");

  return {
    text: title,
    attachments: [
      {
        color: "#ff0000",
        fields: [
          {
            title: "Category",
            value: `${resourceType.toUpperCase()} (FRAUD)`,
            short: true,
          },
          { title: "Shop", value: shopDomain, short: true },
          { title: "Topic", value: topic, short: true },
          {
            title: "Resource ID",
            value: String(resourceId || "Unknown"),
            short: true,
          },
        ],
      },
      {
        color: "#ff4d4f",
        title: "Suspicious Activity",
        text: details,
        mrkdwn_in: ["text"],
      },
    ],
  };
}

function buildCriticalSlackPayload(topic, resourceType, resourceId, shopDomain, payload, previousData) {
  const resourceName =
    payload.title || payload.name || payload.handle || String(resourceId);

  // For themes/publish we can optionally show a tiny diff
  let diffText = "";
  if (previousData) {
    const changes = diffObjects(previousData, payload);
    const lines = [];
    for (const ch of changes.slice(0, 5)) {
      const beforeVal =
        "beforeSummary" in ch ? ch.beforeSummary : summarize(ch.before);
      const afterVal =
        "afterSummary" in ch ? ch.afterSummary : summarize(ch.after);
      lines.push(
        `• \`${ch.path}\`:\n    • Before:\n${beforeVal}\n    • After:\n${afterVal}`
      );
    }
    if (changes.length > 5) {
      lines.push(`… and ${changes.length - 5} more (truncated)`);
    }
    diffText = lines.join("\n");
  }

  let title;
  if (topic === "app/uninstalled") {
    title = `[APP][UNINSTALLED] ${resourceName}`;
  } else if (topic === "themes/publish") {
    title = `[THEME][PUBLISH] ${resourceName}`;
  } else {
    title = `[CRITICAL][${resourceType.toUpperCase()}] ${resourceName}`;
  }

  const baseFields = [
    {
      title: "Category",
      value: resourceType.toUpperCase(),
      short: true,
    },
    {
      title: "Shop",
      value: shopDomain,
      short: true,
    },
    {
      title: "Topic",
      value: topic,
      short: true,
    },
    {
      title: "Resource ID",
      value: String(resourceId || "Unknown"),
      short: true,
    },
  ];

  const attachments = [
    {
      color: topic === "app/uninstalled" ? "#e74c3c" : "#f1c40f",
      fields: baseFields,
    },
  ];

  if (diffText) {
    attachments.push({
      color: "#3b88c3",
      title: "Changes",
      text: diffText,
      mrkdwn_in: ["text"],
    });
  }

  return {
    text: title,
    attachments,
  };
}

// === MAIN HANDLER ===

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "POST");
    return res.end("Method not allowed");
  }

  const rawBody = await getRawBody(req);

  const hmacHeader =
    req.headers["x-shopify-hmac-sha256"] ||
    req.headers["X-Shopify-Hmac-Sha256"];

  const topic = req.headers["x-shopify-topic"] || "unknown_topic";
  const shopDomain =
    req.headers["x-shopify-shop-domain"] || "unknown_shop";

  if (!isValidShopifyHmac(rawBody, hmacHeader)) {
    console.warn("Invalid HMAC", { shopDomain, topic });
    res.statusCode = 401;
    return res.end("Invalid signature");
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch (err) {
    console.error("Invalid JSON", err);
    res.statusCode = 400;
    return res.end("Invalid JSON");
  }

  const { resourceType, action } = parseTopic(topic);
  const resourceId = getResourceId(resourceType, payload);
  const snapshotKey = buildSnapshotKey(
    resourceType,
    resourceId,
    shopDomain
  );

  const previousSnapshot = await getSnapshot(snapshotKey);
  const previousData = previousSnapshot ? previousSnapshot.data : null;

  // Always store the latest snapshot (full payload, PII included)
  await setSnapshot(snapshotKey, {
    shopDomain,
    topic,
    resourceType,
    action,
    resourceId,
    updatedAt: new Date().toISOString(),
    data: payload,
  });

  // Determine anomaly / critical flags
  const isFraudCandidate =
    PII_TOPICS.has(topic) &&
    (topic.startsWith("orders/") || topic.startsWith("checkouts/"));

  const isFraud = isFraudCandidate
    ? isSuspiciousOrderOrCheckout(topic, payload)
    : false;

  const isCriticalEvent = CRITICAL_TOPICS.has(topic);

  // Baseline: first time we see this resource
  if (!previousData) {
    // On first event, only alert if it's fraud or critical
    if (isFraud) {
      const fraudPayload = buildFraudSlackPayload(
        topic,
        resourceType,
        resourceId,
        shopDomain,
        payload
      );
      await sendSlack(fraudPayload);
    } else if (isCriticalEvent) {
      const critPayload = buildCriticalSlackPayload(
        topic,
        resourceType,
        resourceId,
        shopDomain,
        payload,
        null
      );
      await sendSlack(critPayload);
    } else {
      console.log("Baseline snapshot only (no Slack)", {
        shopDomain,
        topic,
        resourceType,
        resourceId,
      });
    }

    res.statusCode = 200;
    return res.end("OK (baseline)");
  }

  // For subsequent events:
  // - If fraud: send fraud alert.
  // - Else if critical (app uninstall, theme publish): send critical alert.
  // - Else: NO Slack (just store snapshot silently).
  if (isFraud) {
    const fraudPayload = buildFraudSlackPayload(
      topic,
      resourceType,
      resourceId,
      shopDomain,
      payload
    );
    await sendSlack(fraudPayload);
  } else if (isCriticalEvent) {
    const critPayload = buildCriticalSlackPayload(
      topic,
      resourceType,
      resourceId,
      shopDomain,
      payload,
      previousData
    );
    await sendSlack(critPayload);
  } else {
    console.log("Non-critical change stored silently", {
      shopDomain,
      topic,
      resourceType,
      resourceId,
    });
  }

  res.statusCode = 200;
  res.end("OK");
};
