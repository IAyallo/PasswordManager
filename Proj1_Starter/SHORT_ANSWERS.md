# Password Manager Assignment: Short Answers

These answers describe the implementation in `password-manager.js` where
applicable. Questions 4–6 ask for design approaches; those approaches are
explanations and are not implemented in this assignment.

## 1. How does the password manager hide password lengths?

Before encryption, the password is encoded as UTF-8. The implementation rejects
values longer than 64 Unicode code points or 256 UTF-8 bytes. It stores the
password bytes in a fixed-width 256-byte field, preceded by a four-byte length
field, and fills the remaining bytes with zeros. Thus, every password produces
a 260-byte plaintext payload. AES-GCM adds a fixed-size authentication tag, so
the resulting ciphertext length does not reveal the password's actual length.
The length field is encrypted along with the password and is only read after
successful decryption.

## 2. How does the password manager prevent swap attacks?

The KVS is indexed by the HMAC of each domain rather than the plaintext domain.
When encrypting a record, the implementation also supplies that domain tag as
AES-GCM additional authenticated data (AAD). When retrieving a record, it
supplies the requested domain's tag again. AES-GCM verifies the AAD along with
the ciphertext and IV. If an attacker moves a record to another domain's KVS
entry, the requested tag no longer matches the tag used to encrypt it, so
authentication fails and the record is rejected. This protection works
independently of the optional trusted checksum.

## 3. Is trusted storage necessary to detect rollback attacks?

To detect rollback when an attacker can replace the entire serialized database,
the program needs some trusted information that the attacker cannot roll back
along with that database. In this implementation, `dump` returns a SHA-256
checksum for storage in a trusted location, and `load` compares a supplied
checksum with a hash of the exact representation string. If the database is
replaced with an older valid snapshot, its checksum will not match the trusted
checksum for the current snapshot.

Without trusted state—such as a protected checksum, a non-rollbackable
counter, or a trusted online service—the old snapshot is internally valid and
cannot be distinguished from the latest one. A checksum stored only beside
the database does not help, because an attacker can roll both back together.

## 4. How would lookup work with a randomized MAC?

A randomized MAC does not give a stable tag that can be recomputed from a
domain alone. One approach is to store each record's MAC tag together with the
public randomness or nonce needed by the MAC's verification procedure. When
looking up a domain, the manager checks that domain against each stored tag
using that tag's nonce, stopping when verification succeeds.

This requires checking up to all records, so lookup becomes O(n) rather than
the O(1) lookup available with a deterministic HMAC index. A separate
deterministic index could restore fast lookup, but that index would reintroduce
a stable domain-derived value and would need its own privacy and integrity
analysis.

## 5. How could the design reduce information leaked about the record count?

Pad the serialized collection with dummy records until its size reaches the
next power-of-two capacity. Make dummy entries indistinguishable from real
entries to someone inspecting the serialized data. Then the observed capacity
reveals a size bucket rather than the exact number of real records: for example,
counts from 5 through 8 would all be represented using capacity 8.

This leaks an approximate record-count scale (the power-of-two bucket), not the
exact count. It costs extra storage and requires distinguishing real entries
from dummies only after unlocking. An empty vault needs a defined minimum
capacity, such as one padded slot.

## 6. How could two users share one site's password without sharing all their passwords?

Encrypt each record with its own random data-encryption key (DEK). For the
shared site, encrypt or wrap that DEK separately for each authorized user's
key-encryption key; Alice and Bob can then both unwrap the key and access that
record. Keep every other site's DEK wrapped only for its owner, so access to
the shared record does not grant access to the rest of either user's vault.

Updates to the shared password must be encrypted under the shared record key
and made available to both users. Removing a user's access requires rekeying
the shared record for the remaining users; it cannot erase information that a
previously authorized user has already copied.

## Implementation note: password verification

The implementation verifies the master password by decrypting a fixed
constant with the derived AES-GCM key. It stores no password hash, but this
does let an attacker with a copy of the serialized vault test password guesses
offline. The per-vault random salt and PBKDF2 work factor slow those guesses;
they do not eliminate this risk. This is an educational assignment
implementation, not a production password manager.
