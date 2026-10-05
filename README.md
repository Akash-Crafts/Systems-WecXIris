# Custom Security Layer (CSL)

## 1. Introduction
This project implements a TLS-inspired secure communication protocol over raw TCP sockets. The goal was to understand secure communication internally instead of relying on a high-level TLS API such as Python's `ssl` module.

The project was developed progressively from basic TCP communication to a secure 1-to-1 terminal chat.

### Implemented Levels
- Level 1 — TCP communication and framing
- Level 2 — ECDH key exchange
- Level 3 — HKDF key derivation
- Level 4 — Handshake authentication
- Level 5 — Authenticated encrypted messaging
- Level 6 — Secure 1-to-1 terminal chat
- Level 7 — Not implemented (multi-party chat room)

---

# 2. Architecture
The project separates networking, framing, protocol definitions, cryptography, handshake logic, and session handling.

```text
src/
├── client.py
├── server.py
├── framing.py
├── protocol.py
├── crypto.py
├── handshake.py
└── session.py
```

### `client.py`
Creates the TCP connection, runs the client handshake, sends/receives chat messages, and handles termination.

### `server.py`
Starts the TCP server, accepts the client connection, runs the server handshake, and handles chat communication.

### `framing.py`
Implements custom TCP framing:
```text
[ TYPE ][ LENGTH ][ PAYLOAD ]
   1 B      4 B      variable
```
`TYPE` identifies the frame, `LENGTH` gives the payload size, and `PAYLOAD` contains the data. This is required because TCP provides a byte stream rather than application-level message boundaries.

### `protocol.py`
Contains frame types, protocol constants, field sizes, and HKDF information labels.

### `crypto.py`
Provides ECDH key generation/shared-secret derivation, public-key serialization, HKDF-SHA256, HMAC-SHA256, AES-GCM, and constant-time comparison.

### `handshake.py`
Implements ECDH exchange, salt generation, session-key derivation, transcript construction, and mutual handshake confirmation.

### `session.py`
Handles sequence numbers, encryption/decryption, AAD construction, replay/reordering detection, and authentication failures.

---

# 3. Cryptographic Protocol

## 3.1 ECDH Key Exchange
The client and server each generate an ephemeral ECDH key pair using `SECP256R1` and exchange public keys over TCP.

```text
SharedSecret = ECDH(OwnPrivateKey, PeerPublicKey)
```

Both sides independently obtain the same shared secret. The raw ECDH secret is not used directly as an encryption key; it is passed to key derivation.

## 3.2 Key Derivation
The client generates a random 32-byte salt and sends it during the handshake. HKDF-SHA256 derives independent session keys:

```text
SharedSecret
     │
    HKDF
     │
     ├── Client → Server Encryption Key
     ├── Server → Client Encryption Key
     ├── Client → Server MAC Key
     └── Server → Client MAC Key
```

Different HKDF `info` labels provide key separation and prevent reuse across purposes or directions.

## 3.3 Handshake Authentication
After key derivation, both sides authenticate the handshake using HMAC-SHA256 over:

```text
Client Public Key + Server Public Key + Salt
```

The client sends `HMAC(Client→Server MAC Key, Transcript)`. The server verifies it and replies with `HMAC(Server→Client MAC Key, Transcript)`, which the client verifies.

Constant-time comparison is used for authentication checks. This confirms that both parties derived the same keys from the same handshake data.

---

# 4. Encrypted Messaging
After the handshake, chat messages are encrypted with AES-GCM. Each outgoing message receives a monotonically increasing sequence number.

```text
[ SEQUENCE NUMBER | NONCE | CIPHERTEXT | AUTH TAG ]
       8 bytes       12 B      variable       16 B
```

A fresh random 12-byte nonce is generated for every message. AES-GCM provides confidentiality and integrity/authentication.

### Replay and Reordering Detection
Each direction maintains its own expected sequence number:

```text
Expected: 0   Received: 0 → accept
Expected: 1   Received: 1 → accept
Expected: 2   Received: 5 → reject
```

Unexpected sequence numbers are rejected, preventing previously valid messages from being replayed or delivered out of order.

---

# 5. Security Properties
- **Confidentiality:** AES-GCM hides chat plaintext from network observers.
- **Integrity:** AES-GCM detects modification of encrypted messages.
- **Authentication:** Handshake HMACs verify that both sides derived the expected session keys.
- **Replay/Reordering Detection:** Sequence numbers reject previously accepted or out-of-order messages.
- **Key Separation:** Independent keys are derived for different directions and purposes.

---

# 6. Running the Project

## Requirements
- Python 3
- `cryptography`

```bash
pip install cryptography
```

## Start the Server
```bash
python src/server.py
```

## Start the Client
Open another terminal:
```bash
python src/client.py
```

The client connects to the server. After the handshake succeeds, both sides can exchange terminal messages.

---

# 7. Development Journey
The project was built incrementally so each layer could be understood and tested before moving to the next.

### Level 1 — TCP Communication
Started with TCP client/server communication and learned sockets, IP addresses, ports, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, and `recv()`.

A key lesson was that TCP is a byte stream and does not preserve application-level message boundaries.

### Level 1 — Framing
Implemented `TYPE + LENGTH + PAYLOAD` framing so the receiver can reconstruct complete messages even when a single `recv()` does not return the full message.

### Level 2 — ECDH
Implemented elliptic-curve Diffie-Hellman and clarified the distinction between private keys, public keys, and the shared secret.

### Level 3 — Key Derivation
Implemented HKDF-SHA256 instead of using the raw DH secret directly. This introduced proper derivation and directional key separation.

### Level 4 — Handshake Confirmation
Implemented transcript-based HMAC confirmation. Both sides had to agree on message order, transcript contents, key labels, serialization, and constant-time verification.

### Level 5 — Encryption
Implemented AES-GCM and learned AEAD, nonces, ciphertext, authentication tags, and AAD. A major debugging issue was ensuring both sides constructed identical AAD and payload fields.

### Level 6 — Secure Chat
Combined all previous layers into a complete 1-to-1 encrypted terminal chat and refactored the implementation into separate modules.

---

# 8. Major Difficulties I Faced

### TCP Framing
`recv(n)` does not guarantee exactly `n` bytes, so the framing layer must continue receiving until the expected number of bytes is collected.

### ECDH
The mathematics behind public-key exchange and common-secret derivation was initially confusing; implementation clarified the relationship between the private key, public key, and shared secret.

### Key Derivation
I initially had to understand why the raw DH secret should not simply become an AES key. HKDF clarified both proper derivation and key separation.

### Handshake Synchronization
Both sides had to agree exactly on message order, transcript contents, key labels, and serialization. Small mismatches caused authentication failures.

### AES-GCM Debugging
Both sides had to use identical nonce handling, ciphertext/tag parsing, sequence numbers, and AAD. Small inconsistencies resulted in `InvalidTag` errors.

### Protocol Organization
As the project grew, keeping everything in one file became difficult to reason about. Separating framing, protocol, cryptography, handshake, and session handling improved debugging and readability.

---

# 9. Design Decisions

### Why ECDH?
ECDH allows two parties to establish a shared secret over an untrusted network without transmitting the secret itself. It was chosen instead of implementing low-level finite-field DH because the `cryptography` library provides a safe primitive while the protocol logic remains custom.

### Why HKDF?
The raw ECDH output is not used directly as an encryption key. HKDF provides structured derivation and key separation through different `info` labels.

### Why AES-GCM?
AES-GCM provides authenticated encryption, combining confidentiality and integrity in one construction. A separate per-message MAC is therefore unnecessary for encrypted chat, while the derived MAC keys are still used for handshake confirmation.

### Why Sequence Numbers?
Encryption and authentication alone do not automatically prevent replay. Sequence numbers allow the receiver to enforce message ordering and reject unexpected values.

### Why Separate Directional Keys?
Separate keys are derived for:
```text
Client → Server
Server → Client
```
This avoids reusing the same symmetric key in both directions and makes the protocol easier to reason about.

### Why Separate Modules?
Separating framing, protocol definitions, cryptography, handshake logic, and session handling makes the implementation easier to test, debug, and extend.

---

# 10. Resources Used
These resources helped me understand the networking and cryptographic concepts and APIs used in the project.

### Networking
- Python Socket Programming — Real Python: https://realpython.com/python-sockets/
- Socket Programming Tutorial: https://youtu.be/JFch3ctY6nE
- TCP framing, length-prefix framing, binary headers, serialization, and endianness references
- Networking concepts: TCP, NAT, public/private IPs, routers, static and dynamic IPs

### Cryptography
- Python `cryptography` documentation
- Diffie-Hellman / ECDH references
- KDF / HKDF: https://www.hexnode.com/blogs/explained/what-is-key-derivation-function-kdf/
- HMAC: https://www.okta.com/en-in/identity-101/hmac/
- AES / AEAD: https://nordlayer.com/blog/aes-encryption/
- References covering discrete logarithms, elliptic-curve mathematics, HMAC, salts, `info`, AAD, and nonces

I used these resources to understand the concepts first and then apply and verify them in the implementation.

---

# 11. Use of AI / External Tools
AI tools were used as learning and debugging aids, not as a replacement for understanding the implementation. They were used for explaining unfamiliar concepts, understanding library APIs, discussing protocol design, reviewing architecture, debugging errors, identifying edge cases, and improving code organization.

I tried to understand the reasoning behind suggestions and verify the implementation locally.

---

# 12. Git / Development History
The project was developed incrementally through commits corresponding to major milestones:

```text
Initial setup
↓
Basic TCP client/server
↓
TCP message framing
↓
Framing tests
↓
ECDH key exchange
↓
Session key derivation
↓
Authenticated handshake
↓
AES-GCM messaging
↓
Secure 1-to-1 chat
↓
Documentation and testing
```

This progression reflects how the protocol was built rather than being implemented as one large system.

---

# 13. What I Would Improve
- Multi-party chat room
- Stronger authenticated identities
- More comprehensive automated tests
- Better error handling and protocol versioning

The next major extension would be Level 7, where multiple clients communicate through a central server.

---

# 14. Demonstrations

### Intermediate Demonstrations
Screen recordings showing TCP communication, framing, ECDH, handshake, encryption, and final chat.

### Final Demonstration
Final 1-to-1 secure chat demonstration:

[Google Drive Video Link]

---

# 15. Conclusion
This project helped me understand secure networking by implementing the major building blocks of a TLS-inspired protocol myself.

```text
TCP
 ↓
Framing
 ↓
ECDH
 ↓
HKDF
 ↓
Handshake Authentication
 ↓
AES-GCM
 ↓
Sequence Numbers
 ↓
Secure Chat
```

The main outcome was understanding how these individual components fit together to create a secure communication protocol.
