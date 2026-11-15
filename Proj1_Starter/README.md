# Password Manager

An educational password-manager library implemented for a Computer Security
and Cryptography assignment. It demonstrates password-based key derivation,
authenticated encryption, HMAC-based lookup, and serialized integrity checks.

> **Warning:** This project is not a production password manager. Do not use it
> to store real passwords or other sensitive information. It is a coursework
> implementation with a limited threat model and no user interface or secure
> storage integration.

## Features

- Derives key material from a master password using PBKDF2-HMAC-SHA-256 with a
  16-byte random salt and 100,000 iterations.
- Separates the record-lookup and encryption keys using distinct HMAC labels.
- Stores each record under an HMAC of its domain, rather than the plaintext
  domain name.
- Encrypts each password independently with AES-GCM and a fresh 12-byte IV.
- Authenticates the domain tag as additional authenticated data to detect
  record swaps.
- Pads password data to a fixed width before encryption to hide password
  length within the supported limits.
- Exports a SHA-256 checksum alongside the serialized keychain so callers can
  keep it in trusted storage and detect changes or rollback.

## Requirements

- Node.js with the Web Crypto API (`crypto.webcrypto.subtle`).
- npm.

## Install and test

From this directory, install the declared dependencies and run the provided
tests:

```sh
npm install
npm test
```

The test suite uses Mocha and Expect.js. The tests cover the provided API,
serialization round-trips, password and checksum rejection, and basic checks
that plaintext secrets are not present in the dump.

## API

```js
const { Keychain } = require("./password-manager");

const keychain = await Keychain.init("a strong master passphrase");
await keychain.set("example.com", "site password");

const password = await keychain.get("example.com");
const missing = await keychain.get("missing.example"); // null when absent
const removed = await keychain.remove("example.com"); // boolean

const [representation, trustedChecksum] = await keychain.dump();
const restored = await Keychain.load(
  "a strong master passphrase",
  representation,
  trustedChecksum
);
```

- `Keychain.init(password)` creates an empty keychain.
- `Keychain.load(password, representation, trustedDataCheck?)` restores a
  keychain. If a trusted checksum is provided, it must match the exact
  representation string.
- `keychain.set(name, value)` inserts or replaces a password.
- `keychain.get(name)` returns a password or `null` when no record exists.
- `keychain.remove(name)` removes a password and returns whether it existed.
- `keychain.dump()` returns `[JSON representation, SHA-256 checksum]`.

Passwords must be strings of no more than 64 Unicode code points and 256
UTF-8 bytes. Exceeding either limit is rejected.

## Security notes and limitations

- **Rollback detection requires trusted state.** Store the checksum returned
  by `dump()` somewhere an attacker who can replace the keychain file cannot
  also modify. Without that trusted value, an old but valid snapshot cannot be
  distinguished from the latest one.
- **Record authentication occurs on retrieval.** `load()` checks the
  representation's structure and password verifier; AES-GCM authentication
  for an individual password record is checked when `get()` decrypts it.
- **Master-password guesses can be tested offline.** The encrypted constant
  allows `load()` to reject a wrong password even for an empty keychain. An
  attacker with a copy of the serialized data can use it to test guesses;
  the random salt and PBKDF2 work factor slow guesses but do not prevent them.
- **This library does not provide secure file handling, memory protection,
  automatic locking, clipboard protections, a user interface, or a full
  production threat model.**

See [SHORT_ANSWERS.md](./SHORT_ANSWERS.md) for the assignment's six short
answers and related design explanations.
