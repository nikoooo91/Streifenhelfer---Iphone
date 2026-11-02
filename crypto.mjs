/** Standard WebCrypto only. Works in modern browsers and Node.js 20+. */
export const FORMAT = 'streifenhelfer-encrypted-payload';
export const VERSION = 1;
export const AAD = `${FORMAT}:v${VERSION}`;
export const PBKDF2_ITERATIONS = 600_000;
export const CHUNK_BYTES = 1024 * 1024;
export const MAX_COMPRESSED_BYTES = 64 * 1024 * 1024;
export const MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
const TAG_BYTES = 16;
const encoder = new TextEncoder();

export class PayloadError extends Error {
  constructor(code, message, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'PayloadError';
    this.code = code;
  }
}

function fail(code, message) { throw new PayloadError(code, message); }
function webCrypto() {
  const value = globalThis.crypto;
  if (!value?.subtle || !value?.getRandomValues) {
    fail('CRYPTO', 'WebCrypto is unavailable. Use HTTPS and a supported browser.');
  }
  return value;
}
function bytes(value, name = 'Data') {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('FORMAT', `${name} must be a Uint8Array or ArrayBuffer.`);
}
function exactKeys(value, expected, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== expected.length ||
      expected.some(key => !Object.hasOwn(value, key))) {
    fail('FORMAT', `Invalid ${name}.`);
  }
}
function toBase64Url(value) {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function fromBase64Url(value, expectedLength, name) {
  // Fixed lengths also bound atob input before allocating memory.
  if (typeof value !== 'string' || value.length !== Math.ceil(expectedLength * 4 / 3) ||
      !/^[A-Za-z0-9_-]+$/.test(value)) fail('FORMAT', `Invalid ${name}.`);
  let result;
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
    result = Uint8Array.from(binary, char => char.charCodeAt(0));
  } catch { fail('FORMAT', `Invalid ${name}.`); }
  if (result.length !== expectedLength || toBase64Url(result) !== value) {
    fail('FORMAT', `Invalid ${name}.`);
  }
  return result;
}
function isHash(value) { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function chunkName(hash, index) {
  return `payload-${hash.slice(0, 16)}-${String(index + 1).padStart(4, '0')}.bin`;
}
export async function sha256(value) {
  const digest = new Uint8Array(await webCrypto().subtle.digest('SHA-256', bytes(value)));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Returns a new 256-bit random access key, never a human-chosen password. */
export function generateAccessKey() {
  return toBase64Url(webCrypto().getRandomValues(new Uint8Array(32)));
}

/** Validates before fetching chunks, allocating ciphertext, or invoking the KDF. */
export function validateManifest(manifest) {
  exactKeys(manifest, ['format', 'version', 'kdf', 'cipher', 'aad', 'bytes',
    'plaintextBytes', 'sha256', 'chunkSize', 'chunks'], 'manifest');
  if (manifest.format !== FORMAT || manifest.version !== VERSION || manifest.aad !== AAD) {
    fail('FORMAT', 'Unsupported payload format, version, or associated data.');
  }
  exactKeys(manifest.kdf, ['name', 'hash', 'iterations', 'salt'], 'KDF parameters');
  if (manifest.kdf.name !== 'PBKDF2' || manifest.kdf.hash !== 'SHA-256' ||
      manifest.kdf.iterations !== PBKDF2_ITERATIONS) fail('FORMAT', 'Unsupported KDF parameters.');
  fromBase64Url(manifest.kdf.salt, 32, 'salt');
  exactKeys(manifest.cipher, ['name', 'keyLength', 'iv', 'tagLength'], 'cipher parameters');
  if (manifest.cipher.name !== 'AES-GCM' || manifest.cipher.keyLength !== 256 ||
      manifest.cipher.tagLength !== 128) fail('FORMAT', 'Unsupported cipher parameters.');
  fromBase64Url(manifest.cipher.iv, 12, 'nonce');
  if (!Number.isSafeInteger(manifest.plaintextBytes) || manifest.plaintextBytes < 1 ||
      manifest.plaintextBytes > MAX_COMPRESSED_BYTES || !Number.isSafeInteger(manifest.bytes) ||
      manifest.bytes !== manifest.plaintextBytes + TAG_BYTES) fail('LIMIT', 'Invalid payload size.');
  if (!isHash(manifest.sha256) || manifest.chunkSize !== CHUNK_BYTES ||
      !Array.isArray(manifest.chunks) ||
      manifest.chunks.length !== Math.ceil(manifest.bytes / CHUNK_BYTES)) {
    fail('FORMAT', 'Invalid ciphertext or chunk metadata.');
  }
  const chunks = manifest.chunks.map((chunk, index) => {
    exactKeys(chunk, ['name', 'sha256', 'size'], 'chunk');
    if (chunk.name !== chunkName(manifest.sha256, index) || !isHash(chunk.sha256) ||
        chunk.size !== Math.min(CHUNK_BYTES, manifest.bytes - index * CHUNK_BYTES)) {
      fail('FORMAT', 'Invalid chunk name, order, hash, or size.');
    }
    return Object.freeze({ ...chunk });
  });
  return Object.freeze({ ...manifest, kdf: Object.freeze({ ...manifest.kdf }),
    cipher: Object.freeze({ ...manifest.cipher }), chunks: Object.freeze(chunks) });
}

/** Nonextractable AES key; password bytes are cleared after PBKDF2. */
export async function deriveKey(password, salt) {
  if (typeof password !== 'string' || password.length < 1 || password.length > 1024) {
    fail('PASSWORD', 'An access key is required.');
  }
  const saltBytes = typeof salt === 'string' ? fromBase64Url(salt, 32, 'salt') : bytes(salt, 'Salt');
  if (saltBytes.length !== 32) fail('FORMAT', 'Invalid salt.');
  const passwordBytes = encoder.encode(password);
  try {
    const material = await webCrypto().subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    return await webCrypto().subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITERATIONS, salt: saltBytes },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { passwordBytes.fill(0); }
}

/** Exactly one AES-GCM operation over the entire gzip, then transport chunking. */
export async function encryptPayload(compressedPayload, password) {
  const plaintext = bytes(compressedPayload, 'Compressed payload');
  if (plaintext.length < 1 || plaintext.length > MAX_COMPRESSED_BYTES) fail('LIMIT', 'Invalid payload size.');
  const salt = webCrypto().getRandomValues(new Uint8Array(32));
  const iv = webCrypto().getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = new Uint8Array(await webCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(AAD), tagLength: 128 }, key, plaintext));
  const hash = await sha256(ciphertext);
  const chunks = [];
  const descriptors = [];
  for (let offset = 0, index = 0; offset < ciphertext.length; offset += CHUNK_BYTES, index++) {
    const data = ciphertext.slice(offset, offset + CHUNK_BYTES);
    const name = chunkName(hash, index);
    descriptors.push({ name, sha256: await sha256(data), size: data.length });
    chunks.push({ name, data });
  }
  const manifest = validateManifest({ format: FORMAT, version: VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITERATIONS, salt: toBase64Url(salt) },
    cipher: { name: 'AES-GCM', keyLength: 256, iv: toBase64Url(iv), tagLength: 128 },
    aad: AAD, bytes: ciphertext.length, plaintextBytes: plaintext.length, sha256: hash,
    chunkSize: CHUNK_BYTES, chunks: descriptors });
  return { manifest, chunks };
}

/**
 * fetchChunk(descriptor, index) returns Uint8Array/ArrayBuffer, never text.
 * Nothing is decompressed or exposed before the complete GCM tag authenticates.
 */
export async function decryptPayload(untrustedManifest, password, fetchChunk) {
  const manifest = validateManifest(untrustedManifest);
  if (typeof fetchChunk !== 'function') fail('FORMAT', 'A chunk loader is required.');
  const ciphertext = new Uint8Array(manifest.bytes);
  try {
    let offset = 0;
    for (let index = 0; index < manifest.chunks.length; index++) {
      const descriptor = manifest.chunks[index];
      let chunk;
      try { chunk = bytes(await fetchChunk(descriptor, index), 'Chunk'); }
      catch (cause) { throw new PayloadError('CHUNK', 'An encrypted part could not be loaded.', cause); }
      if (chunk.length !== descriptor.size || await sha256(chunk) !== descriptor.sha256) {
        fail('CHUNK', 'An encrypted part is incomplete or modified.');
      }
      ciphertext.set(chunk, offset);
      offset += chunk.length;
    }
    if (await sha256(ciphertext) !== manifest.sha256) fail('CHUNK', 'The encrypted payload is modified.');
    const key = await deriveKey(password, manifest.kdf.salt);
    let decrypted;
    try {
      decrypted = new Uint8Array(await webCrypto().subtle.decrypt({ name: 'AES-GCM',
        iv: fromBase64Url(manifest.cipher.iv, 12, 'nonce'),
        additionalData: encoder.encode(AAD), tagLength: 128 }, key, ciphertext));
    } catch (cause) {
      throw new PayloadError('AUTH', 'The access key is incorrect or the payload is damaged.', cause);
    }
    if (decrypted.length !== manifest.plaintextBytes) {
      decrypted.fill(0);
      fail('AUTH', 'The authenticated payload has an invalid size.');
    }
    return decrypted;
  } finally { ciphertext.fill(0); }
}
