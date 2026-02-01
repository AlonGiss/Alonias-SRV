import socket
import threading
from tcp_by_size import send_with_size, recv_by_size
from CryptoUtil import CryptoSession
from protocol import process_request


class SecureServer:
    def __init__(self, host='0.0.0.0', port=11133):
        self.host = host
        self.port = port

    def handle_client(self, sock, addr):
        print(f"[+] Client {addr}")
        crypto = CryptoSession()

        try:
            send_with_size(sock, crypto.get_public_key_frame())

            while True:
                data = recv_by_size(sock)
                if data == b'':
                    continue

                if data.startswith(b'KEY|'):
                    if crypto.receive_encrypted_aes(data[4:]):
                        print("[+] AES session established")
                    else:
                        print("[-] AES key error")
                        break
                    continue

                if data.startswith(b'DATA|'):
                    if not crypto.ready:
                        break

                    plain = crypto.decrypt(data[5:])
                    print("[<]", plain)

                    reply = process_request(plain).encode()
                    encrypted = crypto.encrypt(reply)

                    send_with_size(sock, b'DATA|' + encrypted)

        except Exception as e:
            print("[-] Error:", e)

        finally:
            sock.close()
            print(f"[x] Closed {addr}")

    def serve_forever(self):
        srv = socket.socket()
        srv.bind((self.host, self.port))
        srv.listen(20)

        print(f"[*] Secure server on {self.port}")

        while True:
            cli, addr = srv.accept()
            threading.Thread(
                target=self.handle_client,
                args=(cli, addr),
                daemon=True
            ).start()
