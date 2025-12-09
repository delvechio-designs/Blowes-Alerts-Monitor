// api/blowes-alerts-monitor.js
//
// Shopify monitoring endpoint for Vercel (Node 18).
// - Validates HMAC
// - Stores snapshots (Vercel KV or in-memory)
// - Diffs before/after (using PII-redacted copies for Slack)
// - Categorised Slack alerts in ONE channel
// - Soft Slack rate limiting per resource
// - Flags possible abandoned checkouts
// - Flags possible card testing on orders (transaction failures)
// - Avoids exposing PII in Slack for customers/orders/checkouts
//
// ENV VARS:
//   SHOPIFY_WEBHOOK_SECRET  - API secret key (shpss_...)
//   SLACK_WEBHOOK_URL       - Slack incoming webhook
//   SHOPIFY_ACCESS_TOKEN    - Admin API access token (shpat_...)
//   SHOPIFY_API_VERSION     - e.g. "2025-01"
//   ENABLE_ACTOR_LOOKUP     - "1" to enable Events API actor lookup

const crypto = require("crypto");

// ---- KV client (optional) ---------------------------------------------------

let kv = null;
try {
  kv = require("@vercel/kv").kv;
} catch (e) {
  console.warn(
    "[monitor] @vercel/kv not found, using in-memory snapshots only (non-persistent)."
  );
}

// Fallback in-memory store
const memoryStore = new Map();

async function getSnapshot(key) {
  if (kv) {
    try {
      return await kv.get(key);
    } catch (err) {
      console.error("[monitor] KV get error", err);
    }
  }
  return memoryStore.get(key) || null;
}

async function setSnapshot(key, value) {
  if (kv) {
    try {
      await kv.set(key, value);
      return;
    } catch (err) {
      console.error("[monitor] KV set error", err);
    }
  }
  memoryStore.set(key, value);
}

// ---- Config & constants -----------------------------------------------------

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || null;
const SHOPIFY_ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN || null;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2025-01";
const ENABLE_ACTOR_LOOKUP = process.env.ENABLE_ACTOR_LOOKUP === "1";

// ---- Basic helpers ----------------------------------------------------------

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
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

  const bufferDigest = Buffer.from(digest, "utf8");
  const bufferHeader = Buffer.from(hmacHeader, "utf8");

  if (bufferDigest.length !== bufferHeader.length) return false;

  return crypto.timingSafeEqual(bufferDigest, bufferHeader);
}

function isEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a === "object") {
    try {
      return JSON.stringify(a) === JSON.stringify(b);
    } catch {
      return false;
    }
  }
  return false;
}

function summarizeValue(value) {
  if (value === null || value === undefined) return String(value);

  // Strings
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length > 240) {
      return `${trimmed.slice(0, 180)} … ${trimmed.slice(-40)}`;
    }
    return trimmed;
  }

  // Arrays: show JSON content (truncated) so variants etc. are visible
  if (Array.isArray(value)) {
    try {
      const json = JSON.stringify(value, null, 2);
      const limit = 1500;
      if (json.length > limit) {
        return json.slice(0, limit) + "\n… (truncated)";
      }
      return json;
    } catch {
      return `[Array(${value.length})]`;
    }
  }

  // Objects
  if (typeof value === "object") {
    return "[Object]";
  }

  // Numbers, booleans, etc.
  return String(value);
}

// ---- PII redaction for Slack-facing diffs ----------------------------------

// Full payloads go into snapshots.
// For diffs/Slack, we run a redaction pass to strip PII.
function redactForSlack(resourceType, payload) {
  if (!payload || typeof payload !== "object") return payload;

  const clone = JSON.parse(JSON.stringify(payload));

  const SENSITIVE_KEYS = new Set([
    "email",
    "first_name",
    "last_name",
    "phone",
    "billing_address",
    "shipping_address",
    "default_address",
    "addresses",
    "customer",
    "note",
    "notes",
    "billing_address1",
    "shipping_address1",
    "address1",
    "address2",
    "city",
    "province",
    "zip",
    "postal_code",
    "country",
    "browser_ip",
    "ip",
  ]);

  function scrub(obj) {
    if (!obj || typeof obj !== "object") return;
    if (Array.isArray(obj)) {
      for (const item of obj) scrub(item);
      return;
    }
    for (const key of Object.keys(obj)) {
      const value = obj[key];

      if (SENSITIVE_KEYS.has(key)) {
        if (key === "customer" && value && typeof value === "object") {
          obj[key] = value.id
            ? { id: value.id, note: "[REDACTED CUSTOMER OBJECT]" }
            : "[REDACTED CUSTOMER OBJECT]";
        } else {
          obj[key] = "[REDACTED]";
        }
        continue;
      }

      if (resourceType === "customers" && key === "name") {
        obj[key] = "[REDACTED]";
        continue;
      }

      if (typeof value === "object") scrub(value);
    }
  }

  scrub(clone);
  return clone;
}

// ---- Diffing ---------------------------------------------------------------

function diffObjects(before, after, pathPrefix = "", changes = [], depth = 0) {
  if (depth > 4) return changes;

  if (before === undefined && after === undefined) return changes;

  if (
    typeof before !== "object" ||
    before === null ||
    typeof after !== "object" ||
    after === null
  ) {
    if (!isEqual(before, after)) {
      changes.push({
        path: pathPrefix || "(root)",
        before,
        after,
      });
    }
    return changes;
  }

  if (Array.isArray(before) || Array.isArray(after)) {
    if (!isEqual(before, after)) {
      changes.push({
        path: pathPrefix || "(array)",
        beforeSummary: summarizeValue(before),
        afterSummary: summarizeValue(after),
      });
    }
    return changes;
  }

  const keys = new Set([
    ...Object.keys(before || {}),
    ...Object.keys(after || {}),
  ]);

  for (const key of keys) {
    if (["updated_at", "created_at", "admin_graphql_api_id"].includes(key)) {
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

// ---- Topic / resource helpers ----------------------------------------------

function parseTopic(topic) {
  if (!topic) return { resourceType: "unknown", action: "unknown" };
  const parts = topic.split("/");
  return {
    resourceType: parts[0] || "unknown",
    action: parts[1] || "unknown",
  };
}

function getResourceId(resourceType, payload) {
  if (!payload || typeof payload !== "object") return null;

  switch (resourceType) {
    case "products":
    case "collections":
    case "pages":
    case "blogs":
    case "articles":
    case "customers":
    case "orders":
    case "themes":
    case "discounts":
    case "checkouts":
      return payload.id || null;

    case "inventory_levels":
      return payload.inventory_item_id || payload.id || null;

    case "app":
      return payload.id || payload.domain || "shop";

    default:
      return payload.id || payload.admin_graphql_api_id || null;
  }
}

function buildSnapshotKey(resourceType, resourceId, shopDomain) {
  return `${shopDomain || "shop"}/${resourceType}/${resourceId || "unknown"}`;
}

function getDisplayName(resourceType, payload) {
  if (!payload) return "Unknown";

  if (resourceType === "customers") {
    return `Customer ${payload.id || ""}`.trim();
  }

  if (resourceType === "orders" || resourceType === "checkouts") {
    if (payload.order_number) return `Order #${payload.order_number}`;
    if (payload.name && typeof payload.name === "string") return payload.name;
    return `Order ${payload.id || ""}`.trim();
  }

  return (
    payload.title ||
    payload.name ||
    payload.handle ||
    payload.id ||
    "Unknown"
  );
}

// ---- Category + Slack formatting helpers -----------------------------------

function getSlackCategory(resourceType) {
  if (["products", "collections", "inventory_levels"].includes(resourceType)) {
    return { key: "PRODUCT", emoji: ":package:", color: "#36a64f" };
  }

  if (["pages", "blogs", "articles"].includes(resourceType)) {
    return { key: "CONTENT", emoji: ":memo:", color: "#3b88c3" };
  }

  if (["customers"].includes(resourceType)) {
    return { key: "CUSTOMER", emoji: ":bust_in_silhouette:", color: "#9b59b6" };
  }

  if (["orders"].includes(resourceType)) {
    return { key: "ORDER", emoji: ":shopping_bags:", color: "#e67e22" };
  }

  if (["themes"].includes(resourceType)) {
    return { key: "THEME", emoji: ":art:", color: "#f1c40f" };
  }

  if (["discounts"].includes(resourceType)) {
    return { key: "DISCOUNT", emoji: ":ticket:", color: "#1abc9c" };
  }

  if (["checkouts"].includes(resourceType)) {
    return { key: "CHECKOUT", emoji: ":credit_card:", color: "#2ecc71" };
  }

  if (["app"].includes(resourceType)) {
    return { key: "APP", emoji: ":gear:", color: "#e74c3c" };
  }

  return { key: "OTHER", emoji: ":grey_question:", color: "#95a5a6" };
}

function buildSlackTitle(resourceType, action, categoryKey) {
  return `[${categoryKey}][${action.toUpperCase()}]`;
}

async function sendSlack(payload) {
  if (!SLACK_WEBHOOK_URL) return;
  try {
    await fetch(SLACK_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("[monitor] Slack send error", err);
  }
}

// ---- Actor lookup via Events API -------------------------------------------

async function lookupActor(shopDomain, resourceType, resourceId) {
  if (!ENABLE_ACTOR_LOOKUP || !SHOPIFY_ACCESS_TOKEN || !resourceId) return null;

  const map = {
    products: "Product",
    collections: "Collection",
    pages: "Page",
    blogs: "Blog",
    articles: "Article",
    customers: "Customer",
    orders: "Order",
    inventory_levels: "InventoryLevel",
    themes: "Theme",
    discounts: "DiscountCode",
    checkouts: "Checkout",
    app: "Shop",
  };

  const subjectType = map[resourceType];
  if (!subjectType) return null;

  const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/events.json?subject_type=${encodeURIComponent(
    subjectType
  )}&subject_id=${encodeURIComponent(resourceId)}&limit=1`;

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json",
      },
    });

    if (!res.ok) {
      console.warn("[monitor] actor lookup failed", res.status);
      return null;
    }

    const body = await res.json();
    const ev = body.events && body.events[0];
    if (!ev) return null;

    return (
      ev.author ||
      ev.created_by ||
      ev.message ||
      ev.description ||
      `Event ${ev.id}`
    );
  } catch (err) {
    console.error("[monitor] actor lookup error", err);
    return null;
  }
}

// ---- Slack rate limiting helper --------------------------------------------

async function shouldSkipSlackForRateLimit(rateKey, windowMs) {
  const rlKey = `ratelimit/${rateKey}`;
  const record = await getSnapshot(rlKey);
  const now = Date.now();

  if (record && record.lastAt) {
    const last = new Date(record.lastAt).getTime();
    if (!Number.isNaN(last) && now - last < windowMs) {
      return true;
    }
  }

  await setSnapshot(rlKey, { lastAt: new Date().toISOString() });
  return false;
}

// ---- Checkout abandonment classification -----------------------------------

function classifyCheckoutStatus(payload) {
  if (!payload) return null;

  const completedAt = payload.completed_at;
  const orderId = payload.order_id;
  const createdAtStr = payload.created_at;
  if (!createdAtStr) return null;

  const createdAt = new Date(createdAtStr).getTime();
  if (Number.isNaN(createdAt)) return null;

  const ageMinutes = (Date.now() - createdAt) / 60000;

  if (!completedAt && !orderId && ageMinutes >= 30) {
    return {
      flag: "POSSIBLE_ABANDONED",
      ageMinutes: Math.round(ageMinutes),
    };
  }

  return null;
}

// ---- Card testing suspicion classification ---------------------------------

function classifyCardTesting(resourceType, payload) {
  if (resourceType !== "orders" || !payload) return null;

  const txs = Array.isArray(payload.transactions)
    ? payload.transactions
    : [];

  if (txs.length < 4) return null; // need a few attempts

  const failed = txs.filter((t) => {
    const status = (t.status || "").toLowerCase();
    return status === "error" || status === "failure" || !!t.error_code;
  });

  if (failed.length >= 3 && failed.length / txs.length >= 0.6) {
    const gateways = [
      ...new Set(
        txs
          .map((t) => t.gateway || t.gateway_name)
          .filter(Boolean)
      ),
    ];

    return {
      flag: "POSSIBLE_CARD_TESTING",
      totalTransactions: txs.length,
      failedTransactions: failed.length,
      gateways,
    };
  }

  return null;
}

// ---- Main handler ----------------------------------------------------------

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "POST");
    return res.end("Method not allowed");
  }

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (err) {
    console.error("[monitor] Failed to read body", err);
    res.statusCode = 500;
    return res.end("Failed to read body");
  }

  const hmacHeader =
    req.headers["x-shopify-hmac-sha256"] ||
    req.headers["X-Shopify-Hmac-Sha256"];

  const topic = req.headers["x-shopify-topic"] || "unknown_topic";
  const shopDomain =
    req.headers["x-shopify-shop-domain"] || "unknown_shop";

  if (!isValidShopifyHmac(rawBody, hmacHeader)) {
    console.warn("Invalid HMAC for webhook", { shopDomain, topic });
    res.statusCode = 401;
    return res.end("Invalid signature");
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch (err) {
    console.error("[monitor] Invalid JSON payload", err);
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

  console.log("Valid webhook received", {
    shopDomain,
    topic,
    resourceType,
    action,
    resourceId,
  });

  // Previous snapshot (full, unredacted)
  const previousSnapshot = await getSnapshot(snapshotKey);
  const previousData = previousSnapshot ? previousSnapshot.data : null;

  // Always store current snapshot (full payload) first
  await setSnapshot(snapshotKey, {
    shopDomain,
    topic,
    resourceType,
    action,
    resourceId,
    updatedAt: new Date().toISOString(),
    data: payload,
  });

  // If no previous snapshot: don't send Slack, just remember this as baseline
  if (!previousData) {
    res.statusCode = 200;
    return res.end("OK (baseline snapshot stored)");
  }

  // Build PII-safe copies for diffing / Slack
  const safeCurrent = redactForSlack(resourceType, payload);
  const safePrevious = redactForSlack(resourceType, previousData);

  const changes = diffObjects(safePrevious, safeCurrent);

  // If nothing changed (after redaction), don't send Slack
  if (!changes.length) {
    res.statusCode = 200;
    return res.end("OK (no significant changes)");
  }

  // Optional actor lookup
  const actor = await lookupActor(shopDomain, resourceType, resourceId);

  const category = getSlackCategory(resourceType);
  const title = buildSlackTitle(resourceType, action, category.key);
  const resourceName = getDisplayName(resourceType, payload);

  const statusNotes = [];

  if (resourceType === "checkouts") {
    const statusInfo = classifyCheckoutStatus(payload);
    if (statusInfo && statusInfo.flag === "POSSIBLE_ABANDONED") {
      statusNotes.push(
        `*Status:* Possible abandoned checkout (open for ~${statusInfo.ageMinutes} min, no order created yet).`
      );
    }
  }

  const cardTesting = classifyCardTesting(resourceType, payload);
  if (cardTesting && cardTesting.flag === "POSSIBLE_CARD_TESTING") {
    statusNotes.push(
      `*Status:* Possible card testing detected – ${cardTesting.failedTransactions}/${cardTesting.totalTransactions} failed transactions` +
        (cardTesting.gateways.length
          ? ` via gateways: ${cardTesting.gateways.join(", ")}.`
          : ".")
    );
  }

  const diffLines = [];

  if (statusNotes.length) {
    diffLines.push(...statusNotes);
    diffLines.push(""); // blank line before field-level diffs
  }

  const maxChanges = 12;
  for (const change of changes.slice(0, maxChanges)) {
    const before =
      "beforeSummary" in change
        ? change.beforeSummary
        : summarizeValue(change.before);
    const after =
      "afterSummary" in change
        ? change.afterSummary
        : summarizeValue(change.after);

    diffLines.push(
      `• \`${change.path}\`:\n    • Before:\n${before}\n    • After:\n${after}`
    );
  }
  if (changes.length > maxChanges) {
    diffLines.push(
      `… and ${changes.length - maxChanges} more changes (truncated)`
    );
  }

  const slackPayload = {
    text: `${category.emoji} ${title} ${resourceName}`,
    attachments: [
      {
        color: category.color,
        fields: [
          {
            title: "Category",
            value: category.key,
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
          {
            title: "Actor",
            value: actor || "_Unknown (no recent events)_",
            short: true,
          },
        ],
      },
      {
        color: "#3b88c3",
        title: "Changes",
        text: diffLines.join("\n"),
        mrkdwn_in: ["text"],
      },
    ],
  };

  const rateWindowMs =
    resourceType === "checkouts" ? 5 * 60 * 1000 : 30 * 1000;
  const rateKey = `${snapshotKey}/${action}`;

  const skipSlack = await shouldSkipSlackForRateLimit(
    rateKey,
    rateWindowMs
  );

  if (skipSlack) {
    console.log("Rate-limited Slack alert", { rateKey, resourceType, action });
  } else {
    await sendSlack(slackPayload);
  }

  res.statusCode = 200;
  res.end("OK");
};
