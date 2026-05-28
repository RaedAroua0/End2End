"""
End2End - Server (server.py)
AES-256 password-derived encryption to protect the private key
RSA-2048 encryption to protect the AES exchange
AES-256-GCM encryption for messages
"""

import socket
import os
import sys
import struct
import getpass
from threading import Thread, Event

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 5566

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "server_private.pem")
PUBLIC_KEY_FILE  = os.path.join(KEY_DIR, "server_public.pem")

# ──────────────────────────────────────────────
# RSA KEY MANAGEMENT
# ──────────────────────────────────────────────
def load_or_generate_keys():
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(PRIVATE_KEY_FILE):
        print("[*] First use: generating 2048-bit RSA keys...")

        password = _ask_new_password()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password)
                )
            )

        public_key = private_key.public_key()

        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print("[+] Keys generated and saved.")

    else:
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key_data = f.read()

        max_attempts = 3

        for attempt in range(1, max_attempts + 1):
            password = _ask_password(f"Server private key password ({attempt}/{max_attempts}) : ")

            try:
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=password,
                    backend=default_backend()
                )
                break

            except (ValueError, TypeError):
                if attempt < max_attempts:
                    print(f"[!] Incorrect password. {max_attempts - attempt} remaining attempt(s).")
                else:
                    print("[!] Too many failed attempts. Stopping.")
                    sys.exit(1)

        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    return private_key, public_key


def _ask_password(prompt):
    return getpass.getpass(prompt).encode()


def _ask_new_password():
    while True:
        pw1 = getpass.getpass("Choose a password for your private key : ")
        pw2 = getpass.getpass("Confirm : ")

        if pw1 == pw2 and len(pw1) >= 8:
            return pw1.encode()

        print("[!] Passwords are different or too short (minimum 8 characters).")


# ──────────────────────────────────────────────
# TRANSPORTATION
# ──────────────────────────────────────────────
def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    n = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, n)


def _recv_exact(sock, n) -> bytes:
    buf = b""

    while len(buf) < n:
        chunk = sock.recv(n - len(buf))

        if not chunk:
            raise ConnectionError("Connection closed.")

        buf += chunk

    return buf


# ──────────────────────────────────────────────
# AES-256-GCM
# ──────────────────────────────────────────────
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        None
    )

    return nonce + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]

    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None
    )


# ──────────────────────────────────────────────
# KEY EXCHANGE
# ──────────────────────────────────────────────
def key_exchange_server(sock, public_key):
    """
    1. Sending the server public key
    2. Receiving the client public key
    3. Generating the AES key
    4. Encrypting with the client using pub_client
    5. AES ACK
    """

    # Sending server public key
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    send_frame(sock, pub_bytes)

    # Receiving client public key
    client_pub_pem = recv_frame(sock)

    client_public_key = serialization.load_pem_public_key(
        client_pub_pem,
        backend=default_backend()
    )

    # AES-256 Generation
    aes_key = os.urandom(32)

    # AES encryption with RSA client
    encrypted_aes = client_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    send_frame(sock, encrypted_aes)

    # ACK Verification
    ack_enc = recv_frame(sock)

    ack = aes_decrypt(aes_key, ack_enc)

    if ack != b"OK":
        raise ValueError("Invalid ACK")

    print("[+] AES-256 key shared successfully.")

    return aes_key


# ──────────────────────────────────────────────
# THREADS
# ──────────────────────────────────────────────
stop_event = Event()


def send_messages(sock, aes_key):
    while not stop_event.is_set():
        try:
            msg = input("You → ")

            if msg.lower() == "/quit":
                stop_event.set()
                sock.close()
                break

            encrypted = aes_encrypt(
                aes_key,
                msg.encode("utf-8")
            )

            send_frame(sock, encrypted)

        except (EOFError, OSError):
            stop_event.set()
            break


def receive_messages(sock, aes_key):
    while not stop_event.is_set():
        try:
            data = recv_frame(sock)

            decrypted = aes_decrypt(aes_key, data)

            print(f"\rClient → {decrypted.decode('utf-8')}\nYou → ", end="", flush=True)

        except ConnectionError:
            print("\n[!] Connection closed by the client.")
            stop_event.set()
            break

        except Exception as e:
            print(f"\n[!] Error : {e}")
            stop_event.set()
            break


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    _, public_key = load_or_generate_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))

    server_socket.listen(1)

    print(f"[*] Server waiting on port {PORT}...")

    try:
        client_socket, addr = server_socket.accept()

    except KeyboardInterrupt:
        print("\n[*] Stopping.")
        sys.exit(0)

    print(f"[+] Connected to {addr}")

    try:
        aes_key = key_exchange_server(client_socket, public_key)

    except Exception as e:
        print(f"[!] Failed exchange : {e}")
        client_socket.close()
        sys.exit(1)

    print("[*] Chat started. '/quit' to exit.\n")

    t_recv = Thread(target=receive_messages, args=(client_socket, aes_key), daemon=True)
    t_send = Thread(target=send_messages, args=(client_socket, aes_key), daemon=True)

    t_recv.start()
    t_send.start()

    t_recv.join()
    t_send.join()

    print("[*] Session terminated.")


if __name__ == "__main__":
    main()