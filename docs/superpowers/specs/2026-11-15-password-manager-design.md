# Password Manager Assignment Design

## Goal and scope

Complete the provided Node.js `Keychain` library against the full written
assignment specification. Keep its public API and provided dependencies. Work
will be reviewed in milestones as the user implements it; this design does not
turn the assignment into a user-facing application.

This is an educational implementation, not a recommendation to store real
credentials. The assignment's threat model and API do not cover all protections
expected of a production password manager.

## Design

`Keychain.init` generates a 16-byte random salt and derives key material from
the master password using PBKDF2-HMAC-SHA-256 with 100,000 iterations. Use at
most one PBKDF2 evaluation per operation. Derive separate subkeys for domain
lookup and encryption by evaluating HMAC under the PBKDF2 output with two
fixed, distinct labels. Keep key material out of the serialized state.

The serialized state must not contain a password hash or a password-derived
verifier. To distinguish an incorrect master password even for an empty
keychain, store an AES-GCM encryption of a fixed constant under the derived
encryption key, with its own fresh 12-byte IV. This adds no different kind of
exposure than the encrypted records themselves. `load` decrypts and checks
this constant; an incorrect password or altered verifier fails.

Keep the required `kvs` object, but use the HMAC of each domain as its key.
Encrypt each record independently with AES-GCM using a fresh 12-byte random IV
for every `set`, including updates. Bind the domain tag as authenticated
additional data so moving ciphertext to another key causes authentication to
fail, even when no trusted checksum is supplied.

Encode each password as UTF-8, reject values longer than 64 Unicode code points
or 256 UTF-8 bytes, and encrypt a fixed-width payload containing a length field
and a 256-byte padded value. The original byte length stays inside the
ciphertext. This makes ciphertext lengths independent of password length
without silently truncating input.

The JSON dump contains a format version, the salt, the encrypted fixed
constant and its IV, and the encrypted `kvs`. It contains no plaintext
domains, passwords, master password, or derived keys. `dump` returns this
representation and a SHA-256 checksum computed over the exact representation
string. `load` computes the checksum over the exact input string (without
re-serializing it), checks a supplied trusted checksum, verifies the encrypted
constant, and validates the serialized structure. Record ciphertext is
authenticated when `get` decrypts it; invalid ciphertext or a mismatched
domain binding throws at that point. A supplied trusted checksum detects
tampering and rollback on load. Without it, the implementation cannot promise
to detect deletion or rollback of an otherwise valid old database state.

Preserve the assignment's API and complexity: `set`, `get`, and `remove` use
the HMAC index for O(1) record operations; `load` and `dump` take O(n).

## Review and validation milestones

1. **Key derivation and password verification:** review salt generation,
   PBKDF2 parameters, distinct subkeys, and rejection of an incorrect password,
   including an empty keychain.
2. **Encrypted records and CRUD:** review domain HMAC indexing, AES-GCM
   encryption, fixed-width padding, fresh IVs, domain binding, and CRUD
   behavior.
3. **Serialization and tampering:** review JSON round-trips, optional trusted
   checksum verification, record validation, and explicit swap/rollback
   behavior.

For each milestone, run the provided `npm test` suite. New automated tests are
not required; review the untested security invariants against the threat model
and use focused manual checks when useful. Passing the provided tests alone is
not evidence that the full threat model is met. The full grading suite is
available through Gradescope.

## Short-answer coverage

The design covers question 1 with fixed-width UTF-8 padding, question 2 with
the domain tag as AES-GCM additional authenticated data, and question 3 with
the limitation of detecting rollback without trusted storage.

For question 4, a randomized domain MAC cannot be recomputed as a stable
lookup key. A design using it would need to scan records or decrypt/index them
at load time, trading away the simple deterministic O(1) lookup.

For question 5, pad the serialized record collection with indistinguishable
dummy records to the next power-of-two capacity (using a minimum capacity for
an empty collection). This reveals a capacity bucket rather than the exact
record count, at the cost of extra storage and updating the bucket when it is
full.

For question 6, encrypt a shared record under a separate random record key and
wrap that key for each authorized user's key. Share only the selected record
key; keep each user's other records under keys unavailable to the other user.
These last three ideas are explanatory only and are not assignment features to
implement.
