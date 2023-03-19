addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SECRET_KEY_DATA = encoder.encode('YOUR SECRET KEY');

function normalizeBase64(base64urlencoded) {
  return base64urlencoded.replace(/-/g, '+').replace(/_/g, '/');
}

function base64Decode(str) {
  const normal = normalizeBase64(str);
  return Uint8Array.from(atob(normal), c => c.charCodeAt(0));
}

async function decrypt(encrypted) {
  const encryptedBytes = base64Decode(encrypted);
  const iv = encryptedBytes.subarray(0, 16);
  const cipherText = encryptedBytes.subarray(16);
  
  const decryptKey = await crypto.subtle.importKey(
      'raw',
      SECRET_KEY_DATA,
      'AES-CBC',
      false,
      ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    {name: "AES-CBC", iv: iv},
    decryptKey,
    cipherText
  );

  return decoder.decode(decrypted);
}

async function verify(data, signature) {
  const signatureBytes = base64Decode(signature);
  
  const verifyKey = await crypto.subtle.importKey(
      'raw',
      SECRET_KEY_DATA,
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['verify']
  );

  return crypto.subtle.verify(
    'HMAC',
    verifyKey,
    signatureBytes,
    encoder.encode(data)
  );
}

async function handleRequest(request) {
  // a request looks like: https://your.domain/encryptedurl/signature
  // both encryptedurl and signature are hex encoded

  const urlparts = request.url.split('/');
  const signature = urlparts[urlparts.length-1];
  const encrypted = urlparts[urlparts.length-2];

  // console.log(`encrypted url is ${encrypted}`);
  // console.log(`signature is ${signature}`);

  const url = await decrypt(encrypted);
  // console.log(`url is ${url}`);

  const verified = await verify(url, signature);

  if (!verified)
    return new Response('Invalid signature', { status: 400 })

  return fetch(url, request);
}
