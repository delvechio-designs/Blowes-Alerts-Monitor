// api/blowes-alerts-monitor.js

import crypto from 'crypto';
import { kv } from '@vercel/kv';
import { put as putBlob, get as getBlob } from '@vercel/blob';

/**
 * ENV VARS YOU MUST SET IN VERCEL:
 *
 * SHOPIFY_WEBHOOK_SECRET   -> The webhook signing secret from Shopify
 * SHOPIFY_ACCESS_TOKEN     -> Private app / custom app Admin API token (optional, used for actor lookup)
 * SHOPIFY_API_VERSION      -> e.g. "2025-01"
 * SLACK_WEBHOOK_URL        -> Your Slack Incoming Webhook URL
 *
 * Optional:
 * ENABLE_ACTOR_LOOKUP      -> "true" to attempt actor resolution via Events API
 */

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SHOPIFY_ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2025-01';
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;
const ENABLE_ACTOR_LOOKUP = process.env.ENABLE_ACTOR_LOOKUP === 'true';

// Keys that are usually big HTML blobs (we handle them specially)
const LARGE_HTML_KEYS = [
  'body_html',
  'content',
  'description_html',
  'excerpt_html'
];

// Max size of string values we show in Slack
const MAX_STRING_PREVIEW = 400;

// Max number of changed fields to include in Slack
const MAX_DIFF_ENTRIES = 25;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  const shopDomain = req.headers['x-shopify-shop-domain'];
  const topic = req.headers['x-shopify-topic'];
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  const webhookId = req.headers['x-shopify-webhook-id'] || null;
  const triggeredAt = req.headers['x-shopify-triggered-at'] || null;

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (error) {
    console.error('Error reading raw body', error);
    res.status(400).send('Bad request');
    return;
  }

  if (!verifyShopifyHmac(rawBody, hmacHeader, SHOPIFY_WEBHOOK_SECRET)) {
    console.warn('Invalid HMAC for webhook', { shopDomain, topic });
    res.status(401).send('Invalid signature');
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch (error) {
    console.error('Error parsing JSON payload', error);
    res.status(400).send('Invalid JSON');
    return;
  }

  try {
    const identity = getResourceIdentity(topic, payload);
    const category = getCategoryForTopic(topic);

    const snapshotKey = buildSnapshotKey(shopDomain, identity.type, identity.id);
    const previousMeta = await kv.get(snapshotKey);

    let beforeSnapshot = null;

    if (previousMeta && previousMeta.blobKey) {
      try {
        const blob = await getBlob(previousMeta.blobKey);
        if (blob && blob.body) {
          const text = await blob.text();
          beforeSnapshot = JSON.parse(text);
        }
      } catch (e) {
        console.warn('Could not load previous snapshot blob', e);
      }
    }

    const afterSnapshot = payload;

    // Compute diff
    const diff = computeDiff(beforeSnapshot, afterSnapshot, {
      maxEntries: MAX_DIFF_ENTRIES,
      maxStringLength: MAX_STRING_PREVIEW,
      largeHtmlKeys: LARGE_HTML_KEYS
    });

    // Attempt actor resolution (best-effort)
    let actor = null;
    if (ENABLE_ACTOR_LOOKUP && SHOPIFY_ACCESS_TOKEN && shopDomain && identity.eventsSubjectType) {
      try {
        actor = await resolveActorFromEvents({
          shopDomain,
          accessToken: SHOPIFY_ACCESS_TOKEN,
          apiVersion: SHOPIFY_API_VERSION,
          subjectType: identity.eventsSubjectType,
          subjectId: identity.eventsSubjectId || identity.id
        });
      } catch (e) {
        console.warn('Actor resolution failed', e);
      }
    }

    // Store new snapshot in Blob
    const blobPath = `shopify-monitor/${shopDomain}/${identity.type}/${identity.id}/${Date.now()}.json`;
    const blob = await putBlob(blobPath, JSON.stringify(afterSnapshot, null, 2), {
      contentType: 'application/json'
    });

    // Update KV metadata
    const metaToStore = {
      shopDomain,
      type: identity.type,
      resourceId: identity.id,
      resourceName: identity.name,
      topic,
      lastUpdatedAt: afterSnapshot.updated_at || triggeredAt || new Date().toISOString(),
      blobKey: blob.pathname, // blob.pathname is the key used to retrieve it
      previousBlobKey: previousMeta ? previousMeta.blobKey : null,
      webhookId,
    };

    await kv.set(snapshotKey, metaToStore);

    // Send Slack notification
    if (SLACK_WEBHOOK_URL) {
      const slackPayload = buildSlackPayload({
        category,
        topic,
        shopDomain,
        identity,
        diff,
        actor,
        meta: metaToStore
      });

      await postToSlack(SLACK_WEBHOOK_URL, slackPayload);
    }

    // MUST respond quickly so Shopify doesn't retry
    res.status(200).send('OK');
  } catch (error) {
    console.error('Error processing webhook', error);
    // Return 500 so Shopify will retry according to their retry policy
    res.status(500).send('Internal error');
  }
}

/**
 * Utils
 */

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyShopifyHmac(rawBody, hmacHeader, secret) {
  if (!secret || !hmacHeader) return false;
  const digest = crypto
    .createHmac('sha256', secret)
    .update(rawBody, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
}

function buildSnapshotKey(shopDomain, type, id) {
  return `shopify-monitor:${shopDomain}:${type}:${id}`;
}

/**
 * Identify resource type + name + event subject mapping for Events API.
 */
function getResourceIdentity(topic, body) {
  // Default
  let type = 'unknown';
  let name = body && (body.title || body.name || body.handle || body.email || String(body.id));
  let eventsSubjectType = null;
  let eventsSubjectId = null;

  if (topic.startsWith('products/')) {
    type = 'product';
    name = body.title || `Product #${body.id}`;
    eventsSubjectType = 'Product';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('collections/')) {
    type = 'collection';
    name = body.title || `Collection #${body.id}`;
    eventsSubjectType = 'Collection';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('pages/')) {
    type = 'page';
    name = body.title || `Page #${body.id}`;
    eventsSubjectType = 'Page';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('blogs/')) {
    type = 'blog';
    name = body.title || `Blog #${body.id}`;
    eventsSubjectType = 'Blog';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('articles/')) {
    type = 'article';
    name = body.title || `Article #${body.id}`;
    eventsSubjectType = 'Article';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('customers/')) {
    type = 'customer';
    name = body.email || `${body.first_name || ''} ${body.last_name || ''}`.trim();
    eventsSubjectType = 'Customer';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('orders/')) {
    type = 'order';
    name = body.name || `Order #${body.id}`;
    eventsSubjectType = 'Order';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('inventory_levels/')) {
    type = 'inventory_level';
    name = `Inventory Level ${body.inventory_item_id}/${body.location_id}`;
    eventsSubjectType = 'InventoryLevel';
    eventsSubjectId = body.id || body.inventory_item_id;
  } else if (topic.startsWith('themes/')) {
    type = 'theme';
    name = body.name || `Theme #${body.id}`;
    eventsSubjectType = 'Theme';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('discounts/') || topic.startsWith('price_rules/')) {
    type = 'discount';
    name = body.title || `Discount #${body.id}`;
    eventsSubjectType = 'PriceRule';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('checkouts/')) {
    type = 'checkout';
    name = body.token || `Checkout #${body.id}`;
    eventsSubjectType = 'Checkout';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('carts/')) {
    type = 'cart';
    name = body.token || `Cart #${body.id}`;
    eventsSubjectType = 'Cart';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('shop/')) {
    type = 'shop';
    name = body.name || shopDomain;
    eventsSubjectType = 'Shop';
    eventsSubjectId = body.id;
  } else if (topic.startsWith('app/uninstalled')) {
    type = 'app';
    name = 'This app';
  }

  return {
    type,
    id: body.id || body.token || 'unknown',
    name,
    eventsSubjectType,
    eventsSubjectId
  };
}

/**
 * Categorize by topic for Slack headline.
 */
function getCategoryForTopic(topic) {
  const map = {
    'products/create': '[PRODUCT CREATE]',
    'products/update': '[PRODUCT UPDATE]',
    'products/delete': '[PRODUCT DELETE]',
    'collections/create': '[COLLECTION CREATE]',
    'collections/update': '[COLLECTION UPDATE]',
    'collections/delete': '[COLLECTION DELETE]',
    'pages/create': '[PAGE CREATE]',
    'pages/update': '[PAGE EDIT]',
    'pages/delete': '[PAGE DELETE]',
    'articles/create': '[BLOG POST CREATE]',
    'articles/update': '[BLOG POST EDIT]',
    'articles/delete': '[BLOG POST DELETE]',
    'customers/create': '[CUSTOMER CREATE]',
    'customers/update': '[CUSTOMER UPDATE]',
    'customers/delete': '[CUSTOMER DELETE]',
    'orders/create': '[ORDER CREATE]',
    'orders/updated': '[ORDER UPDATE]',
    'orders/fulfilled': '[ORDER FULFILLED]',
    'orders/paid': '[ORDER PAID]',
    'inventory_levels/update': '[INVENTORY UPDATE]',
    'themes/create': '[THEME CREATE]',
    'themes/update': '[THEME EDIT]',
    'themes/delete': '[THEME DELETE]',
    'themes/publish': '[THEME PUBLISH]',
    'discounts/create': '[DISCOUNT CREATE]',
    'discounts/update': '[DISCOUNT UPDATE]',
    'discounts/delete': '[DISCOUNT DELETE]',
    'price_rules/create': '[DISCOUNT CREATE]',
    'price_rules/update': '[DISCOUNT UPDATE]',
    'price_rules/delete': '[DISCOUNT DELETE]',
    'checkouts/create': '[CHECKOUT CREATE]',
    'checkouts/update': '[CHECKOUT UPDATE]',
    'checkouts/delete': '[CHECKOUT DELETE]',
    'carts/create': '[CART CREATE]',
    'carts/update': '[CART UPDATE]',
    'app/uninstalled': '[APP UNINSTALLED]',
    'shop/update': '[SHOP UPDATE]'
  };
  return map[topic] || '[SHOPIFY EVENT]';
}

/**
 * Generic shallow+recursive diff with protections.
 */
function computeDiff(before, after, options = {}) {
  if (!before) {
    return {
      type: 'created',
      changes: summarizeObject(after, options)
    };
  }
  if (!after) {
    return {
      type: 'deleted',
      changes: summarizeObject(before, options)
    };
  }

  const { maxEntries = 25, maxStringLength = 400, largeHtmlKeys = [] } = options;

  const changes = [];
  const visitedKeys = new Set([...Object.keys(before), ...Object.keys(after)]);

  function addChange(path, oldVal, newVal, meta = {}) {
    if (changes.length >= maxEntries) return;
    changes.push({
      path,
      before: summarizeValue(oldVal, { maxStringLength }),
      after: summarizeValue(newVal, { maxStringLength }),
      ...meta
    });
  }

  function recurse(path, a, b, depth) {
    if (changes.length >= maxEntries) return;
    const keyPath = path.join('.');

    // Special handling for large HTML fields: only mark changed/unchanged, do not dump full content
    const lastKey = path[path.length - 1];
    if (largeHtmlKeys.includes(lastKey)) {
      if (a !== b) {
        addChange(keyPath, '[HTML content changed]', '[HTML content changed]', {
          isLargeHtml: true
        });
      }
      return;
    }

    if (typeof a !== 'object' || a === null || typeof b !== 'object' || b === null) {
      if (!isEqual(a, b)) {
        addChange(keyPath, a, b);
      }
      return;
    }

    if (depth > 3) {
      if (!isEqual(a, b)) {
        addChange(keyPath, '[complex object changed]', '[complex object changed]', {
          truncated: true
        });
      }
      return;
    }

    const subKeys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
    for (const k of subKeys) {
      if (changes.length >= maxEntries) return;
      recurse([...path, k], a ? a[k] : undefined, b ? b[k] : undefined, depth + 1);
    }
  }

  for (const key of visitedKeys) {
    if (changes.length >= maxEntries) break;
    recurse([key], before[key], after[key], 1);
  }

  return {
    type: 'updated',
    changes
  };
}

function summarizeObject(obj, options = {}) {
  const { maxEntries = 25 } = options;
  const out = {};
  if (!obj || typeof obj !== 'object') return obj;
  let count = 0;
  for (const [key, val] of Object.entries(obj)) {
    if (count >= maxEntries) {
      out['__truncated__'] = 'More fields omitted';
      break;
    }
    out[key] = summarizeValue(val, options);
    count++;
  }
  return out;
}

function summarizeValue(value, { maxStringLength = 400 } = {}) {
  if (typeof value === 'string') {
    if (value.length > maxStringLength) {
      return value.slice(0, maxStringLength) + '… [truncated]';
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return [];
    if (value.length > 5) {
      return value.slice(0, 5).map(v => summarizeValue(v, { maxStringLength })).concat(['… more items']);
    }
    return value.map(v => summarizeValue(v, { maxStringLength }));
  }
  if (value && typeof value === 'object') {
    // Shallow summary for nested objects
    const out = {};
    let count = 0;
    for (const [k, v] of Object.entries(value)) {
      if (count >= 5) {
        out['__truncated__'] = 'More fields omitted';
        break;
      }
      out[k] = summarizeValue(v, { maxStringLength });
      count++;
    }
    return out;
  }
  return value;
}

function isEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Best-effort actor resolution using Shopify Events API.
 * NOTE: This requires appropriate scopes and may not always be exact.
 */
async function resolveActorFromEvents({ shopDomain, accessToken, apiVersion, subjectType, subjectId }) {
  if (!subjectType || !subjectId) return null;

  const url = `https://${shopDomain}/admin/api/${apiVersion}/events.json?subject_type=${encodeURIComponent(subjectType)}&subject_id=${encodeURIComponent(subjectId)}&limit=5`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'X-Shopify-Access-Token': accessToken,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    console.warn('Events API call failed', response.status, await response.text());
    return null;
  }

  const data = await response.json();
  if (!data || !data.events || !data.events.length) return null;

  // Take the most recent event as the probable actor
  const event = data.events[0];
  return {
    author: event.author || null,
    message: event.message || null,
    created_at: event.created_at || null
  };
}

/**
 * Slack integration
 */
async function postToSlack(webhookUrl, payload) {
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    console.error('Slack webhook failed', res.status, await res.text());
  }
}

function buildSlackPayload({ category, topic, shopDomain, identity, diff, actor, meta }) {
  const title = `${category} ${identity.type.toUpperCase()} • ${identity.name || identity.id}`;
  const changesPreview = formatDiffForSlack(diff);

  const actorText = actor
    ? `*Actor*: ${actor.author || 'Unknown'}\n*Last event*: ${actor.message || ''}`.trim()
    : '*Actor*: Unknown (see Shopify admin activity)';

  const fields = [
    {
      type: 'mrkdwn',
      text: `*Shop*: \`${shopDomain}\`\n*Topic*: \`${topic}\`\n*Resource*: \`${identity.type}\` #\`${identity.id}\``
    },
    {
      type: 'mrkdwn',
      text: actorText
    }
  ];

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: title, emoji: true }
    },
    {
      type: 'section',
      fields
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: changesPreview || '_No significant field-level changes detected_'
      }
    }
  ];

  return {
    text: title,
    blocks
  };
}

function formatDiffForSlack(diff) {
  if (!diff) return '';
  if (diff.type === 'created') {
    return `*Change type*: Created\n\`\`\`${JSON.stringify(diff.changes, null, 2)}\`\`\``;
  }
  if (diff.type === 'deleted') {
    return `*Change type*: Deleted\n\`\`\`${JSON.stringify(diff.changes, null, 2)}\`\`\``;
  }
  if (!diff.changes || !diff.changes.length) return '*Change type*: Updated (no diff details)';

  const lines = [];
  lines.push(`*Change type*: Updated`);
  lines.push('');
  for (const c of diff.changes) {
    lines.push(`• *${c.path}*`);
    lines.push(`   – Before: \`${stringifyForSlack(c.before)}\``);
    lines.push(`   – After: \`${stringifyForSlack(c.after)}\``);
  }

  return lines.join('\n');
}

function stringifyForSlack(value) {
  if (typeof value === 'string') {
    return value.replace(/`/g, "'");
  }
  return JSON.stringify(value).replace(/`/g, "'");
}
