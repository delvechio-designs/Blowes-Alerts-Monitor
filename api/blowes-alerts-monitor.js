// api/blowes-alerts-monitor.js
const crypto = require('crypto');

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || null;

// Helper: read raw request body (needed for correct HMAC)
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Helper: verify Shopify HMAC using raw body
function isValidShopifyHmac(rawBody, hmacHeader) {
  if (!hmacHeader || !SHOPIFY_WEBHOOK_SECRET) return false;

  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('base64');

  // timing-safe compare
  const bufferDigest = Buffer.from(digest, 'utf8');
  const bufferHeader = Buffer.from(hmacHeader, 'utf8');

  if (bufferDigest.length !== bufferHeader.length) return false;

  return crypto.timingSafeEqual(bufferDigest, bufferHeader);
}

// Helper: simple Slack notify (fire-and-forget)
async function sendSlackMessage(payload) {
  if (!SLACK_WEBHOOK_URL) return;

  try {
    await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('Failed to send Slack message', err);
  }
}

module.exports = async (req, res) => {
  // 1. Only allow POST
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Allow', 'POST');
    return res.end('Method not allowed');
  }

  try {
    // 2. Grab raw body
    const rawBody = await getRawBody(req);

    const hmacHeader =
      req.headers['x-shopify-hmac-sha256'] ||
      req.headers['X-Shopify-Hmac-Sha256'];

    const topic = req.headers['x-shopify-topic'] || 'unknown_topic';
    const shopDomain =
      req.headers['x-shopify-shop-domain'] || 'unknown_shop';

    // 3. Verify HMAC
    const valid = isValidShopifyHmac(rawBody, hmacHeader);

    if (!valid) {
      console.warn('Invalid HMAC for webhook', {
        shopDomain,
        topic,
      });
      res.statusCode = 401;
      return res.end('Invalid signature');
    }

    // 4. Parse body now that HMAC is verified
    let payload = null;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      console.error('Failed to parse webhook body as JSON', err);
    }

    console.log('Valid webhook received', {
      shopDomain,
      topic,
    });

    // 5. Send a simple Slack message so we can see it’s working
    await sendSlackMessage({
      text: `[*SHOPIFY WEBHOOK*] \`${topic}\` from *${shopDomain}*`,
      attachments: [
        {
          color: '#36a64f',
          fields: [
            {
              title: 'Topic',
              value: topic,
              short: true,
            },
            {
              title: 'Shop',
              value: shopDomain,
              short: true,
            },
          ],
        },
      ],
    });

    res.statusCode = 200;
    return res.end('OK');
  } catch (err) {
    console.error('Error handling webhook', err);
    res.statusCode = 500;
    return res.end('Internal server error');
  }
};
