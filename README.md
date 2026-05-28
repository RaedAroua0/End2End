````md
# End2End — Encrypted Chat

A simple 1-to-1 encrypted chat application built in Python for educational and portfolio purposes.

**Password-derived AES-256** protects RSA-2048 private keys · **RSA-2048** secures the AES session key exchange · **AES-256-GCM** encrypts messages.

---

## Disclaimer

This project is an educational / academic cybersecurity project and is **not intended for production use**.

It was designed to explore:
- hybrid cryptography,
- RSA key exchange,
- AES-GCM authenticated encryption,
- secure private key storage,
- socket programming,
- and secure communication concepts.

---

## Installation

```bash
pip install -r requirements.txt
````

---

## Launch

### Server side (listening machine)

```bash
python server.py
```

### Client side (connecting machine)

Edit `HOST` inside `client.py` with the server IP address, then run:

```bash
python client.py
```

---

## Using ngrok (Internet)

```bash
# On the server machine:
ngrok tcp 5566
```

Copy the generated ngrok address (example: `0.tcp.eu.ngrok.io:12345`)
and place it into `HOST` and `PORT` inside `client.py`.

---

## Cryptographic Architecture

The project uses hybrid encryption:

| Purpose                     | Technology                                 |
| --------------------------- | ------------------------------------------ |
| RSA private key protection  | Password-derived AES-256 (encrypted PKCS8) |
| Secure session key exchange | RSA-2048 + OAEP-SHA256                     |
| Message encryption          | AES-256-GCM                                |

---

## Key Exchange Protocol

```text
Server                              Client
  |                                    |
  |──── server RSA public key ───────▶|
  |◀──── client RSA public key ───────|
  |                                    |
  |  [server generates AES-256 key]    |
  |──── AES encrypted with RSA ──────▶|
  |◀──── AES-encrypted ACK "OK" ──────|
  |                                    |
  |════ AES-256-GCM encrypted chat ═══|
```

---

## Encryption Workflow

### 1. RSA Private Key Protection

On first launch:

* an RSA-2048 key pair is generated;
* the user chooses a password;
* the password derives an AES key used to encrypt the private `.pem` file.

Private RSA keys are therefore never stored in plaintext on disk.

---

### 2. AES Session Key Exchange

The server:

1. receives the client's RSA public key;
2. generates a random AES-256 key;
3. encrypts the AES key using the client's RSA public key;
4. sends the encrypted result to the client.

The client then decrypts it using its RSA private key.

---

### 3. Message Encryption

All messages use:

* AES-256-GCM;
* a random 12-byte nonce;
* an integrated authentication tag.

AES-GCM guarantees:

* confidentiality;
* integrity;
* tamper detection.

---

## Key Storage

| File                      | Content              | Protection         |
| ------------------------- | -------------------- | ------------------ |
| `keys/server_private.pem` | RSA-2048 private key | Password-encrypted |
| `keys/server_public.pem`  | RSA public key       | Public             |
| `keys/client_private.pem` | RSA-2048 private key | Password-encrypted |
| `keys/client_public.pem`  | RSA public key       | Public             |

Keys are automatically generated on first launch.

Never share:

* `_private.pem` files

---

## Commands

| Command | Action                     |
| ------- | -------------------------- |
| `/quit` | Cleanly closes the session |

---

## Current Security Properties

The project currently provides:

* encrypted communications;
* message integrity;
* local private key protection.

The project does NOT yet provide:

* strong peer authentication;
* full protection against active MITM attacks;

---

## Known Limitations

* No peer authentication system
* No multi-client support
* No network anonymity (public IP remains visible)
* No graphical interface

---

## Possible Future Improvements (v2)

* RSA/ECDSA handshake signatures
* Multi-client support
* Encrypted relay system
* Graphical interface

```
```
