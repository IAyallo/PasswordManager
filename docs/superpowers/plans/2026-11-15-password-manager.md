# Password Manager Assignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the starter `Keychain` library to match the assignment API and full written security requirements.

**Architecture:** Keep implementation in the existing `password-manager.js`. Derive separate lookup and encryption keys from one PBKDF2-HMAC-SHA-256 operation, store records by HMAC(domain), and encrypt fixed-width password payloads with AES-GCM. Use an AES-GCM-encrypted constant to check the master password, bind each record to its lookup tag, and use the exact serialized string for the optional trusted checksum.

**Tech Stack:** Node.js, built-in `crypto.webcrypto.subtle`, provided `lib.js` helpers, Mocha/Expect.js tests.

---

## Files and responsibilities

- Modify `Proj1_Starter\password-manager.js`: constructor, key derivation helpers, `init`, `load`, `dump`, `set`, `get`, and `remove`.
- Read but do not modify `Proj1_Starter\lib.js`: string/byte conversion, Base64 encoding, and secure random bytes are already provided.
- Read but do not modify `Proj1_Starter\test\test-password-manager.js`: the existing suite checks the public API, round trips, wrong-password/checksum failures, encrypted dump content, and the serialized `kvs` shape.
- Do not add test files. Run the provided suite at each milestone. The starter does not test all security properties, so also review the code against this plan and use small manual checks only where an existing test cannot exercise a requirement.

All commands below run from `Proj1_Starter\`. In this workspace, the installed Mocha package is available but its Windows `.cmd` shim is missing, so invoke Mocha with `node .\node_modules\mocha\bin\mocha` instead of `npm test`. No commit steps are included because the workspace is not a Git repository.

### Task 1: Derive keys and verify the master password

**Files:**
- Modify: `Proj1_Starter\password-manager.js`
- Read: `Proj1_Starter\lib.js`

- [ ] **Step 1: Add module-level crypto helpers and constants**

Use the existing `subtle`, `stringToBuffer`, `encodeBuffer`, `decodeBuffer`, and `getRandomBytes` imports. Keep the 100,000-iteration setting, and define the algorithm parameters in one place:

```js
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const AES_GCM_IV_LENGTH = 12;
const PASSWORD_MAX_CODE_POINTS = 64;
const PASSWORD_MAX_BYTES = 256;
const PASSWORD_PADDING_BYTES = 256;
const FORMAT_VERSION = 1;
const VERIFIER_PLAINTEXT = "keychain-password-check-v1";
const LOOKUP_KEY_LABEL = "keychain-lookup-v1";
const ENCRYPTION_KEY_LABEL = "keychain-encryption-v1";
```

- [ ] **Step 2: Implement one PBKDF2 derivation and two labeled HMAC subkeys**

Import the UTF-8 master password as PBKDF2 material, call `subtle.deriveBits` once with SHA-256, 100,000 iterations, and the serialized 16-byte salt, then import those bits as an HMAC-SHA-256 key. Sign each distinct label with that key. Import one result as an HMAC signing key for lookup tags and the other as a non-extractable AES-GCM key with `encrypt` and `decrypt` usages. Do not serialize the PBKDF2 output or either subkey.

- [ ] **Step 3: Add an encrypted-constant password verifier**

Encrypt `VERIFIER_PLAINTEXT` with the derived AES-GCM key, a fresh 12-byte IV, and no password hash or password-derived verifier in the JSON state. Save the IV and ciphertext as Base64 strings. During load, decrypt the verifier and compare its plaintext to the fixed constant; throw an `Error` if decryption fails or the plaintext differs. This permits wrong-password rejection even when `kvs` is empty.

- [ ] **Step 4: Implement constructor and `Keychain.init`**

Have the constructor receive initialized public state and secret CryptoKeys. Keep the serializable values in `this.data` and non-serializable keys in `this.secrets`. `init(password)` creates the salt, derives keys once, creates the encrypted verifier, and initializes `kvs` as an empty object. Ensure the serialized state has the `kvs` field required by the existing tests.

- [ ] **Step 5: Review the initialization milestone**

Run:

```powershell
node .\node_modules\mocha\bin\mocha --grep "inits without an error|incorrect password"
```

Expected: matching initialization and non-empty wrong-password tests pass. Also inspect the empty-keychain path in `load`: it must verify the encrypted constant before returning, not rely on attempting to decrypt a record.

### Task 2: Implement encrypted, padded CRUD records

**Files:**
- Modify: `Proj1_Starter\password-manager.js`
- Read: `Proj1_Starter\lib.js`
- Read: `Proj1_Starter\test\test-password-manager.js`

- [ ] **Step 1: Add a domain-tag helper**

UTF-8 encode the domain, sign it with the lookup HMAC key, and Base64-encode the result. Use that tag as the `kvs` property key; never put the raw domain in serialized state.

- [ ] **Step 2: Add fixed-width password encoding**

Count Unicode code points and UTF-8 bytes before encoding. Reject input longer than 64 code points or 256 UTF-8 bytes. Create a 260-byte plaintext payload: a four-byte unsigned big-endian UTF-8 byte length followed by the UTF-8 bytes and zero padding to 256 bytes. This keeps the AES-GCM plaintext length constant while retaining the exact original bytes inside encryption.

- [ ] **Step 3: Implement `set(name, value)`**

Compute the domain tag and use its UTF-8 bytes as AES-GCM additional authenticated data. Encrypt the fixed-width payload with the derived AES key and a new 12-byte random IV on every call, including an update. Store only Base64 IV and ciphertext under the tag. Updating the same domain replaces its record.

- [ ] **Step 4: Implement `get(name)`**

Compute the domain tag and return `null` if it is not an own property of `kvs`. Otherwise, Base64-decode its IV and ciphertext, decrypt with the domain tag as additional authenticated data, validate the fixed payload length and embedded byte length, then decode exactly that many UTF-8 bytes. Throw an `Error` if decoding, shape validation, or AES-GCM authentication fails; a ciphertext moved to another domain tag must fail authentication.

- [ ] **Step 5: Implement `remove(name)`**

Compute the domain tag. If it is not present as an own property, return `false`; otherwise delete that record and return `true`.

- [ ] **Step 6: Review CRUD against the existing tests**

Run:

```powershell
node .\node_modules\mocha\bin\mocha --grep "can set and retrieve|returns null|can remove|returns false if there is no password"
```

Expected: matching CRUD tests pass. Confirm the existing helper calls are awaited; Web Crypto operations are asynchronous.

### Task 3: Implement serialization, checksum, and loading

**Files:**
- Modify: `Proj1_Starter\password-manager.js`
- Read: `Proj1_Starter\test\test-password-manager.js`

- [ ] **Step 1: Implement `dump()`**

Call `JSON.stringify(this.data)` exactly once and keep that exact string as the representation. Compute SHA-256 over its UTF-8 bytes and return `[representation, base64Checksum]`. Do not include secret keys, plaintext domains, passwords, or the master password.

- [ ] **Step 2: Implement structure validation for `load()`**

Parse the supplied representation and reject an unsupported version, missing salt/verifier/`kvs`, invalid encoded field types, a salt that does not decode to 16 bytes, or malformed record objects. Do not decrypt every record during load: the provided tests do not require a swapped record to fail at load, and record authentication occurs when `get` reads it.

- [ ] **Step 3: Implement trusted-check validation**

When `trustedDataCheck !== undefined`, compute SHA-256 directly over the exact `representation` string argument and compare its Base64 digest to the supplied checksum. Do not stringify the parsed object to compute this digest. Throw an `Error` on mismatch before accepting the state.

- [ ] **Step 4: Finish `Keychain.load(password, representation, trustedDataCheck)`**

After any trusted-check comparison, parse and validate the representation, decode the salt, derive keys once, and verify the encrypted constant. Construct a ready-to-use `Keychain` with the parsed `kvs`, verifier, salt, and secret keys. An invalid password, checksum, or state must reject rather than return a success-shaped fallback.

- [ ] **Step 5: Review serialization against the existing tests**

Run:

```powershell
node .\node_modules\mocha\bin\mocha --grep "dump and restore|checksum is wrong|incorrect password|doesn't store|includes a kvs object"
```

Expected: matching restore, checksum, wrong-password, encrypted-content, and `kvs`-shape tests pass. Check that the checksum covers the exact dump string and that a valid empty keychain also rejects a wrong password.

### Task 4: Complete assignment review and short answers

**Files:**
- Review: `Proj1_Starter\password-manager.js`
- Review: `Proj1_Starter\test\test-password-manager.js`
- Reference: `proj1 documentation.pdf`, Section 6

- [ ] **Step 1: Run the complete provided suite**

Run:

```powershell
node .\node_modules\mocha\bin\mocha
```

Expected: all provided tests pass. If a failure appears, fix the root cause in `password-manager.js` and rerun the failing selection followed by the complete suite.

- [ ] **Step 2: Check security requirements not exercised by visible tests**

Review the implementation against the following concrete invariants: lookup keys are HMAC(domain); every record and verifier uses a fresh 12-byte IV; the encrypted password payload is always 260 bytes before AES-GCM; record AAD is the HMAC domain tag; and changing a record’s tag causes `get` to reject. Verify that changing the salt invalidates the encrypted verifier and that a supplied trusted checksum rejects any changed dump. These checks do not require adding a test file.

- [ ] **Step 3: Prepare the six Section 6 short answers separately**

Explain: (1) fixed-width UTF-8 padding hides lengths; (2) AES-GCM additional authenticated data binds records to domains; (3) without trusted state, a valid old snapshot cannot be distinguished from the latest state; (4) randomized MAC lookup requires scanning records or building an index at load, with a performance cost; (5) indistinguishable dummy records padded to a power-of-two capacity hide the exact record count within its bucket; and (6) a per-record data key wrapped for each authorized user shares only that entry’s key. Questions 4–6 are explanations, not features to implement.

- [ ] **Step 4: Run the full grading suite**

Upload the completed `Proj1_Starter\password-manager.js` to Gradescope as described in the assignment. The local provided tests are useful but do not establish that every grading or threat-model property is satisfied.
