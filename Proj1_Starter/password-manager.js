"use strict";

/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const AES_GCM_IV_LENGTH = 12;
const PASSWORD_MAX_CODE_POINTS = 64;
const PASSWORD_MAX_BYTES = 256;
const PASSWORD_PADDING_BYTES = 256;
const PASSWORD_LENGTH_BYTES = 4;
const AES_GCM_TAG_BYTES = 16;
const FORMAT_VERSION = 1;
const VERIFIER_PLAINTEXT = "keychain-password-check-v1";
const LOOKUP_KEY_LABEL = "keychain-lookup-v1";
const ENCRYPTION_KEY_LABEL = "keychain-encryption-v1";
// AES-GCM appends a 16-byte authentication tag to the encrypted plaintext.
const VERIFIER_CIPHERTEXT_BYTES =
  Buffer.byteLength(VERIFIER_PLAINTEXT, "utf8") + AES_GCM_TAG_BYTES;

/********* Crypto Helpers ********/

function requireString(value, label) {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
}

// Buffer.from accepts malformed Base64 permissively; require a canonical round-trip.
function decodeCanonicalBase64(value, label) {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a Base64 string`);
  }
  const decoded = decodeBuffer(value);
  if (encodeBuffer(decoded) !== value) {
    throw new Error(`${label} is not valid canonical Base64`);
  }
  return decoded;
}

/**
 * Runs PBKDF2 once, then separates its output into independent lookup and
 * encryption keys using HMAC labels.
 */
async function deriveKeys(password, salt) {
  requireString(password, "password");
  const passwordBytes = stringToBuffer(password);
  const passwordKey = await subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  // The Web Crypto key is non-extractable; clear the temporary Node buffer promptly.
  passwordBytes.fill(0);

  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS
    },
    passwordKey,
    256
  );
  const rootKey = await subtle.importKey(
    "raw",
    derivedBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Distinct labels keep lookup and encryption keys cryptographically separate.
  const lookupBytes = await subtle.sign(
    "HMAC",
    rootKey,
    stringToBuffer(LOOKUP_KEY_LABEL)
  );
  const encryptionBytes = await subtle.sign(
    "HMAC",
    rootKey,
    stringToBuffer(ENCRYPTION_KEY_LABEL)
  );

  const lookupKey = await subtle.importKey(
    "raw",
    lookupBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const encryptionKey = await subtle.importKey(
    "raw",
    encryptionBytes,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );

  return { lookupKey, encryptionKey };
}

async function encryptVerifier(encryptionKey) {
  const iv = getRandomBytes(AES_GCM_IV_LENGTH);
  // An encrypted constant verifies passwords without storing a password hash.
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    stringToBuffer(VERIFIER_PLAINTEXT)
  );
  return {
    iv: encodeBuffer(iv),
    ciphertext: encodeBuffer(ciphertext)
  };
}

/** Rejects an incorrect password without storing a password hash in the vault. */
async function verifyPassword(encryptionKey, verifier) {
  const iv = decodeCanonicalBase64(verifier.iv, "verifier IV");
  const ciphertext = decodeCanonicalBase64(
    verifier.ciphertext,
    "verifier ciphertext"
  );
  if (iv.length !== AES_GCM_IV_LENGTH || ciphertext.length <= AES_GCM_TAG_BYTES) {
    throw new Error("Invalid password verifier");
  }

  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv },
      encryptionKey,
      ciphertext
    );
  } catch (error) {
    if (error && error.name === "OperationError") {
      throw new Error("Incorrect master password or invalid password verifier");
    }
    throw error;
  }

  if (bufferToString(plaintext) !== VERIFIER_PLAINTEXT) {
    throw new Error("Incorrect master password or invalid password verifier");
  }
}

// Use an exact schema so serialized values cannot smuggle unexpected fields.
function exactKeys(object, expectedKeys) {
  const keys = Object.keys(object);
  return keys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(object, key));
}

// Validate only the record's envelope here; authenticate its contents on get().
function validateRecord(record, label, expectedCiphertextBytes) {
  if (
    record === null ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    !exactKeys(record, ["iv", "ciphertext"])
  ) {
    throw new Error(`Invalid ${label}`);
  }

  const iv = decodeCanonicalBase64(record.iv, `${label} IV`);
  const ciphertext = decodeCanonicalBase64(
    record.ciphertext,
    `${label} ciphertext`
  );
  if (
    iv.length !== AES_GCM_IV_LENGTH ||
    ciphertext.length !== expectedCiphertextBytes
  ) {
    throw new Error(`Invalid ${label}`);
  }
}

/** Checks the serialized envelope and every record's encoded shape before loading. */
function validateSerializedData(data) {
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    !exactKeys(data, ["version", "salt", "verifier", "kvs"]) ||
    data.version !== FORMAT_VERSION ||
    data.kvs === null ||
    typeof data.kvs !== "object" ||
    Array.isArray(data.kvs)
  ) {
    throw new Error("Invalid keychain representation");
  }

  const salt = decodeCanonicalBase64(data.salt, "salt");
  if (salt.length !== SALT_LENGTH) {
    throw new Error("Invalid keychain salt");
  }

  validateRecord(
    data.verifier,
    "password verifier",
    VERIFIER_CIPHERTEXT_BYTES
  );

  for (const tag of Object.keys(data.kvs)) {
    const tagBytes = decodeCanonicalBase64(tag, "domain tag");
    if (tagBytes.length !== 32) {
      throw new Error("Invalid domain tag");
    }
    validateRecord(
      data.kvs[tag],
      "keychain record",
      PASSWORD_LENGTH_BYTES + PASSWORD_PADDING_BYTES + AES_GCM_TAG_BYTES
    );
  }

  return salt;
}

/********* Keychain Implementation ********/

class Keychain {
  /**
   * @param {object} data Serializable salt, verifier, version, and encrypted records.
   * @param {object} secrets Non-serializable CryptoKeys used while the vault is unlocked.
   */
  constructor(data, secrets) {
    this.data = data;
    this.secrets = secrets;
  }

  /**
   * Creates an empty keychain with the given master password.
   *
   * @param {string} password
   * @returns {Promise<Keychain>}
   */
  static async init(password) {
    requireString(password, "password");
    const salt = getRandomBytes(SALT_LENGTH);
    const secrets = await deriveKeys(password, salt);
    const data = {
      version: FORMAT_VERSION,
      salt: encodeBuffer(salt),
      verifier: await encryptVerifier(secrets.encryptionKey),
      // A null-prototype object avoids inherited properties being mistaken for records.
      kvs: Object.create(null)
    };
    return new Keychain(data, secrets);
  }

  /**
   * Loads a keychain representation and optionally verifies its trusted hash.
   *
   * @param {string} password
   * @param {string} representation
   * @param {string} trustedDataCheck
   * @returns {Promise<Keychain>}
   */
  static async load(password, representation, trustedDataCheck) {
    requireString(password, "password");
    requireString(representation, "representation");

    if (trustedDataCheck !== undefined) {
      requireString(trustedDataCheck, "trustedDataCheck");
      const actualCheck = encodeBuffer(
        await subtle.digest("SHA-256", stringToBuffer(representation))
      );
      if (actualCheck !== trustedDataCheck) {
        throw new Error("Keychain integrity check failed");
      }
    }

    // Hash the original text above; parsing and re-stringifying could change its bytes.
    const data = JSON.parse(representation);
    const salt = validateSerializedData(data);
    const secrets = await deriveKeys(password, salt);
    await verifyPassword(secrets.encryptionKey, data.verifier);

    // Records are authenticated on get; this keeps loading independent of vault size.
    const kvs = Object.create(null);
    for (const tag of Object.keys(data.kvs)) {
      kvs[tag] = data.kvs[tag];
    }
    data.kvs = kvs;
    return new Keychain(data, secrets);
  }

  /**
   * Serializes the keychain and returns its SHA-256 integrity check.
   *
   * @returns {Promise<[string, string]>}
   */
  async dump() {
    const representation = JSON.stringify(this.data);
    // Hash the exact serialized string returned to the caller for trusted storage.
    const checksum = encodeBuffer(
      await subtle.digest("SHA-256", stringToBuffer(representation))
    );
    return [representation, checksum];
  }

  /** HMACs a domain so its name never appears as a serialized KVS key. */
  async getDomainTag(name) {
    requireString(name, "name");
    const tag = await subtle.sign(
      "HMAC",
      this.secrets.lookupKey,
      stringToBuffer(name)
    );
    return encodeBuffer(tag);
  }

  /**
   * Encodes a password into a fixed-size UTF-8 payload so ciphertext length
   * does not reveal the password's length.
   */
  async encodePassword(value) {
    requireString(value, "value");
    const codePointLength = Array.from(value).length;
    const passwordBytes = stringToBuffer(value);
    if (
      codePointLength > PASSWORD_MAX_CODE_POINTS ||
      passwordBytes.length > PASSWORD_MAX_BYTES ||
      bufferToString(passwordBytes) !== value
    ) {
      passwordBytes.fill(0);
      throw new RangeError("Password exceeds the supported UTF-8 length");
    }

    // A fixed-width plaintext hides password length from ciphertext observers.
    const payload = Buffer.alloc(
      PASSWORD_LENGTH_BYTES + PASSWORD_PADDING_BYTES
    );
    payload.writeUInt32BE(passwordBytes.length, 0);
    passwordBytes.copy(payload, PASSWORD_LENGTH_BYTES);
    passwordBytes.fill(0);
    return payload;
  }

  /**
   * Encrypts one record with a fresh IV. The HMAC domain tag is authenticated
   * as additional data so ciphertext cannot be moved to another domain.
   */
  async set(name, value) {
    const tag = await this.getDomainTag(name);
    const payload = await this.encodePassword(value);
    const iv = getRandomBytes(AES_GCM_IV_LENGTH);
    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        // Binding the tag prevents a valid record being swapped to another domain.
        additionalData: stringToBuffer(tag)
      },
      this.secrets.encryptionKey,
      payload
    );
    payload.fill(0);
    this.data.kvs[tag] = {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(ciphertext)
    };
  }

  /**
   * Looks up one record and authenticates it before returning its password.
   * Authentication errors are surfaced instead of returning corrupted data.
   */
  async get(name) {
    const tag = await this.getDomainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return null;
    }

    const record = this.data.kvs[tag];
    const iv = decodeCanonicalBase64(record.iv, "record IV");
    const ciphertext = decodeCanonicalBase64(
      record.ciphertext,
      "record ciphertext"
    );

    let plaintext;
    try {
      plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: stringToBuffer(tag)
        },
        this.secrets.encryptionKey,
        ciphertext
      );
    } catch (error) {
      if (error && error.name === "OperationError") {
        throw new Error("Keychain record authentication failed");
      }
      throw error;
    }

    const payload = Buffer.from(plaintext);
    if (
      payload.length !== PASSWORD_LENGTH_BYTES + PASSWORD_PADDING_BYTES
    ) {
      throw new Error("Invalid keychain record payload");
    }

    const passwordLength = payload.readUInt32BE(0);
    if (passwordLength > PASSWORD_MAX_BYTES) {
      throw new Error("Invalid keychain record password length");
    }
    for (
      let index = PASSWORD_LENGTH_BYTES + passwordLength;
      index < payload.length;
      index++
    ) {
      if (payload[index] !== 0) {
        throw new Error("Invalid keychain record padding");
      }
    }

    const passwordBytes = payload.subarray(
      PASSWORD_LENGTH_BYTES,
      PASSWORD_LENGTH_BYTES + passwordLength
    );
    let password;
    try {
      password = new TextDecoder("utf-8", { fatal: true }).decode(passwordBytes);
    } catch (error) {
      if (error instanceof TypeError) {
        throw new Error("Invalid UTF-8 in keychain record");
      }
      throw error;
    }
    if (Array.from(password).length > PASSWORD_MAX_CODE_POINTS) {
      throw new Error("Invalid keychain record password length");
    }
    return password;
  }

  /** Removes a record using its HMAC index; returns false when no entry exists. */
  async remove(name) {
    const tag = await this.getDomainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return false;
    }
    delete this.data.kvs[tag];
    return true;
  }
}

module.exports = { Keychain };
