# End2End — Encrypted Chat

A lightweight 1-to-1 encrypted chat application written in Python.
Implements hybrid cryptography using RSA and AES to secure communications over TCP sockets.

This project was built for educational and portfolio purposes to explore:

* hybrid encryption,
* authenticated encryption,
* secure private key storage,
* socket programming,
* and secure communication protocols.

---

# Features

* RSA-2048 key generation
* AES-256-GCM encrypted messaging
* Password-protected RSA private keys
* OAEP-SHA256 secure key exchange
* Automatic key generation on first launch
* Threaded send/receive architecture
* TCP socket communication
* Minimal terminal interface

---

# Technologies Used

| Layer                  | Technology                              |
| ---------------------- | --------------------------------------- |
| Language               | Python 3                                |
| Asymmetric Encryption  | RSA-2048                                |
| Symmetric Encryption   | AES-256-GCM                             |
| RSA Padding            | OAEP + SHA-256                          |
| Private Key Protection | Password-derived AES encryption (PKCS8) |
| Networking             | TCP sockets                             |
| Concurrency            | Python threading                        |
| Dependencies           | `cryptography`                          |

---

# Project Structure

```text
End2End/
│
├── server.py                # Encrypted chat server
├── client.py                # Encrypted chat client
├── requirements.txt
├── README.md
├── .gitignore
│
└── keys/
    ├── server_private.pem
    ├── server_public.pem
    ├── client_private.pem
    └── client_public.pem
```

The `keys/` directory is automatically generated during first execution.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/End2End.git
cd End2End
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the server:

```bash
python server.py
```

Run the client:

```bash
python client.py
```

---

# Usage

## Server

The server listens for incoming TCP connections:

```bash
python server.py
```

---

## Client

Edit the `HOST` variable inside `client.py` with the server IP address:

```python
HOST = "127.0.0.1"
```

Then launch:

```bash
python client.py
```

---

# Using ngrok (Internet Access)

On the server machine:

```bash
ngrok tcp 5566
```

Example output:

```text
tcp://0.tcp.eu.ngrok.io:12345
```

Use:

* `0.tcp.eu.ngrok.io` as `HOST`
* `12345` as `PORT`

inside `client.py`.

---

# Cryptographic Architecture

The application uses hybrid encryption:

| Purpose                     | Technology                      |
| --------------------------- | ------------------------------- |
| Private RSA key protection  | Password-derived AES encryption |
| Secure session key exchange | RSA-2048 + OAEP-SHA256          |
| Message encryption          | AES-256-GCM                     |

---

# Key Exchange Protocol

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

# Encryption Workflow

## 1. RSA Private Key Protection

On first launch:

* an RSA-2048 key pair is generated;
* the user chooses a password;
* the password is used to encrypt the private `.pem` key file.

Private RSA keys are never stored in plaintext on disk.

---

## 2. AES Session Key Exchange

The server:

1. receives the client's RSA public key;
2. generates a random AES-256 session key;
3. encrypts the AES key using the client RSA public key;
4. sends the encrypted AES key to the client.

The client decrypts the AES key using its RSA private key.

---

## 3. Message Encryption

All messages use:

* AES-256-GCM;
* a random 12-byte nonce;
* an integrated authentication tag.

AES-GCM provides:

* confidentiality;
* integrity;
* tamper detection.

---

# Key Storage

| File                      | Content              | Protection         |
| ------------------------- | -------------------- | ------------------ |
| `keys/server_private.pem` | RSA-2048 private key | Password-encrypted |
| `keys/server_public.pem`  | RSA public key       | Public             |
| `keys/client_private.pem` | RSA-2048 private key | Password-encrypted |
| `keys/client_public.pem`  | RSA public key       | Public             |

Never share:

* `_private.pem` files

---

# Commands

| Command | Action                     |
| ------- | -------------------------- |
| `/quit` | Cleanly closes the session |

---

# Security Notes

The project currently provides:

* encrypted communications;
* authenticated encryption via AES-GCM;
* local private key protection.

The project does NOT yet provide:

* peer authentication;
* protection against active MITM attacks;
* Perfect Forward Secrecy (PFS).

---

# Known Limitations

* No peer authentication system
* No multi-client support
* No graphical interface
* No relay infrastructure
* Public IP remains visible during direct connections

---

# Possible Future Improvements

* RSA/ECDSA handshake signatures
* X25519 ephemeral key exchange
* Perfect Forward Secrecy (PFS)
* Multi-client support
* Encrypted relay system
* GUI application
* File transfer support

---

# Disclaimer

This project is intended for educational and portfolio purposes only.
It is NOT designed for production-grade secure communications.

For real-world secure messaging, use audited protocols and applications such as:

* Signal
* Matrix
* Session
* Wire

---

# Author

Developed by **AROUA Raed**
GitHub: https://github.com/RaedAroua0