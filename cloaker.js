addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SECRET_KEY_DATA = encoder.encode('YOUR SECRET KEY');

function normalizeBase64(base64urlencoded) {
  return base64urlencoded.replace(/\+/g, '-').replace(/\//g, '_');
}

function base64Encode(arr) {
  const base64 = btoa(String.fromCharCode.apply(null, arr));
  const base64urlencoded = normalizeBase64(base64);
  return base64urlencoded;
}

async function encrypt(data) {
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const encryptKey = await crypto.subtle.importKey(
      'raw',
      SECRET_KEY_DATA,
      'AES-CBC',
      false,
      ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    {name: "AES-CBC", iv: iv},
    encryptKey,
    encoder.encode(data)
  );

  const encryptedBytes = new Uint8Array(iv.length + encrypted.byteLength);
  encryptedBytes.set(iv);
  encryptedBytes.set(new Uint8Array(encrypted), iv.length);

  return base64Encode(encryptedBytes);
}

async function sign(data) {
  const signingKey = await crypto.subtle.importKey(
      'raw',
      SECRET_KEY_DATA,
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign']
  );

  const signatureBytes = await crypto.subtle.sign(
    'HMAC',
    signingKey,
    encoder.encode(data)
  );

  const signature = base64Encode(new Uint8Array(signatureBytes));

  return signature;
}

async function handleRequest(request) {
  const url = new URL(request.url);

  // Get the query parameter named "target" from the request URL
  const target = url.searchParams.get("target");

  // Return a 400 Bad Request error if the "target" parameter is missing
  if (!target) {
    return new Response('Missing "target" parameter', { status: 400 })
  }

  // Encrypt the target URL
  const encrypted = await encrypt(target);

  // Sign the encrypted URL
  const signature = await sign(target);

  // Construct the final URL with the encrypted URL and signature
  const finalUrl = `${url.protocol}//${url.host}/${encrypted}/${signature}`;

  return new Response(finalUrl);
}
