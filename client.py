"""
End2End - Client (client.py)
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

HOST = "127.0.0.1"
PORT = 5566

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "client_private.pem")
PUBLIC_KEY_FILE  = os.path.join(KEY_DIR, "client_public.pem")


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

            password = _ask_password(
                f"Client private key password ({attempt}/{max_attempts}) : "
            )

            try:
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=password,
                    backend=default_backend()
                )

                break

            except (ValueError, TypeError):

                if attempt < max_attempts:
                    print(f"[!] Incorrect password.")

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
        pw1 = getpass.getpass("Choose a password : ")
        pw2 = getpass.getpass("Confirm : ")

        if pw1 == pw2 and len(pw1) >= 8:
            return pw1.encode()

        print("[!] Passwords that are different or too short (minimum 8 characters).")


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


def key_exchange_client(sock, private_key, public_key):

    # Reception pub server
    server_pub_pem = recv_frame(sock)

    # Sending pub client
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    send_frame(sock, pub_bytes)

    # AES reception encrypted RSA
    encrypted_aes = recv_frame(sock)

    aes_key = private_key.decrypt(
        encrypted_aes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # ACK
    send_frame(sock, aes_encrypt(aes_key, b"OK"))

    print("[+] AES key received.")

    return aes_key


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

            print(f"\rServer → {decrypted.decode('utf-8')}\nYou → ", end="", flush=True)

        except ConnectionError:
            print("\n[!] Connection closed.")
            stop_event.set()
            break

        except Exception as e:
            print(f"\n[!] Error : {e}")
            stop_event.set()
            break


def main():

    private_key, public_key = load_or_generate_keys()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((HOST, PORT))

    except ConnectionRefusedError:
        print(f"[!] Unable to reach {HOST}:{PORT}")
        sys.exit(1)

    print(f"[+] Connected to {HOST}:{PORT}")

    try:
        aes_key = key_exchange_client(
            sock,
            private_key,
            public_key
        )

    except Exception as e:
        print(f"[!] Failed exchange : {e}")
        sock.close()
        sys.exit(1)

    print("[*] Chat started. '/quit' to exit.\n")

    t_recv = Thread(target=receive_messages, args=(sock, aes_key), daemon=True)
    t_send = Thread(target=send_messages, args=(sock, aes_key), daemon=True)

    t_recv.start()
    t_send.start()

    t_recv.join()
    t_send.join()

    print("[*] Session terminated.")


if __name__ == "__main__":
    main()