// api/blowes-alerts-monitor.js
// Minimal version: never sends Slack if there is no previous snapshot.

const crypto = require("crypto");

// --- Config ---
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || null;

// in-memory snapshots (you can switch to @vercel/kv later if you want)
const memoryStore = new Map();

async function getSnapshot(key) {
  return memoryStore.get(key) || null;
}

async function setSnapshot(key, value) {
  memoryStore.set(key, value);
}

// --- Helpers ---
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

  const b1 = Buffer.from(digest, "utf8");
  const b2 = Buffer.from(hmacHeader, "utf8");
  if (b1.length !== b2.length) return false;
  return crypto.timingSafeEqual(b1, b2);
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
  if (typeof value === "object") return "[Object]";
  return String(value);
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
    const next = pathPrefix ? `${pathPrefix}.${key}` : key;
    diffObjects(
      before ? before[key] : undefined,
      after ? after[key] : undefined,
      next,
      changes,
      depth + 1
    );
  }

  return changes;
}

async function sendSlack(payload) {
  if (!SLACK_WEBHOOK_URL) return;
  await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

// --- MAIN HANDLER ---
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
  const snapshotKey = buildSnapshotKey(resourceType, resourceId, shopDomain);

  const previousSnapshot = await getSnapshot(snapshotKey);
  const previousData = previousSnapshot ? previousSnapshot.data : null;

  // Always store current snapshot
  await setSnapshot(snapshotKey, {
    shopDomain,
    topic,
    resourceType,
    action,
    resourceId,
    updatedAt: new Date().toISOString(),
    data: payload,
  });

  // *** IMPORTANT: if no previous snapshot, EXIT with NO Slack ***
  if (!previousData) {
    console.log("Baseline snapshot only (no Slack)", {
      shopDomain,
      topic,
      resourceType,
      resourceId,
    });
    res.statusCode = 200;
    return res.end("OK (baseline only)");
  }

  const changes = diffObjects(previousData, payload);

  // If nothing actually changed, also do nothing
  if (!changes.length) {
    console.log("No meaningful changes, skipping Slack", {
      shopDomain,
      topic,
      resourceType,
      resourceId,
    });
    res.statusCode = 200;
    return res.end("OK (no changes)");
  }

  // Build Slack message (NO 'New resource – no previous snapshot' anywhere)
  const diffLines = [];
  const maxChanges = 12;
  for (const ch of changes.slice(0, maxChanges)) {
    const before =
      "beforeSummary" in ch ? ch.beforeSummary : summarize(ch.before);
    const after =
      "afterSummary" in ch ? ch.afterSummary : summarize(ch.after);
    diffLines.push(
      `• \`${ch.path}\`:\n    • Before:\n${before}\n    • After:\n${after}`
    );
  }
  if (changes.length > maxChanges) {
    diffLines.push(`… and ${changes.length - maxChanges} more (truncated)`);
  }

  const title = `[${resourceType.toUpperCase()}][${action.toUpperCase()}]`;
  const resourceName =
    payload.title || payload.name || payload.handle || String(resourceId);

  const slackPayload = {
    text: `${title} ${resourceName}`,
    attachments: [
      {
        color: "#36a64f",
        fields: [
          { title: "Category", value: resourceType.toUpperCase(), short: true },
          { title: "Shop", value: shopDomain, short: true },
          { title: "Topic", value: topic, short: true },
          { title: "Resource ID", value: String(resourceId || "Unknown"), short: true },
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

  await sendSlack(slackPayload);

  res.statusCode = 200;
  res.end("OK");
};
