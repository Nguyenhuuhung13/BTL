import socket
import json
import base64
import os
import time
from datetime import datetime, timedelta, timezone
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad

# --- Cấu hình Client ---
HOST = '127.0.0.1'
PORT = 65432
FILE_TO_SEND = 'email.txt' # Bạn có thể đổi tên file này

# --- Tạo và lưu khóa của Người Gửi (nếu chưa có) ---
print("--- Phía Người Gửi (Client) ---")
if not os.path.exists("sender_private.pem"):
    print("Đang tạo cặp khóa RSA 2048-bit cho Người Gửi...")
    sender_key = RSA.generate(2048)
    with open("sender_private.pem", "wb") as f:
        f.write(sender_key.export_key())
    with open("sender_public.pem", "wb") as f:
        f.write(sender_key.publickey().export_key())
    print("Đã tạo và lưu khóa của Người Gửi.")
else:
    print("Đã tìm thấy khóa của Người Gửi.")

# --- Nạp khóa riêng của Người Gửi để ký ---
with open("sender_private.pem", "rb") as f:
    sender_private_key = RSA.import_key(f.read())

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Đã kết nối tới server {HOST}:{PORT}")

        s.sendall(b"Hello!")
        response = s.recv(1024).decode()
        if response != "Ready!":
            print("Handshake thất bại.")
            s.close()
            exit()

        receiver_public_key_data = s.recv(1024)
        receiver_public_key = RSA.import_key(receiver_public_key_data)

        session_key = get_random_bytes(16)

        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        metadata_str = f"filename: {FILE_TO_SEND}, timestamp: {timestamp}"
        metadata = metadata_str.encode('utf-8')

        h_meta = SHA512.new(metadata)
        signature = pkcs1_15.new(sender_private_key).sign(h_meta)

        cipher_rsa = PKCS1_v1_5.new(receiver_public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        # THÊM LOGIC ĐO THỜI GIAN VÀO ĐÂY
        start_time = time.time()

        with open(FILE_TO_SEND, 'rb') as f:
            file_data = f.read()
        padded_data = pad(file_data, AES.block_size)

        iv = get_random_bytes(AES.block_size)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(padded_data)

        end_time = time.time()
        encryption_time = end_time - start_time
        # In ra thời gian mã hóa
        print(f" -> Mã hóa file thành công. (Thời gian mã hóa: {encryption_time:.6f} giây)")
        # =================================================================

        expiration_time = datetime.now(timezone.utc) + timedelta(hours=24)
        expiration_iso = expiration_time.isoformat().replace('+00:00', 'Z')

        hash_payload = iv + ciphertext + expiration_iso.encode('utf-8')
        h_final = SHA512.new(hash_payload)
        hash_hex = h_final.hexdigest()

        data_packet = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "cipher": base64.b64encode(ciphertext).decode('utf-8'),
            "hash": hash_hex,
            "sig": base64.b64encode(signature).decode('utf-8'),
            "exp": expiration_iso,
            "session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "metadata": base64.b64encode(metadata).decode('utf-8')
        }

        s.sendall(json.dumps(data_packet).encode('utf-8'))
        print("\n[HOÀN TẤT] Đã gửi gói tin mã hóa. Đang chờ phản hồi...")

        final_status = s.recv(1024).decode()
        print(f"[PHẢN HỒI TỪ SERVER]: {final_status}")

except FileNotFoundError:
    # Thêm thông báo lỗi thân thiện nếu không tìm thấy file
    print(f"\n[LỖI] Không tìm thấy file '{FILE_TO_SEND}'.")
    print("Vui lòng kiểm tra lại tên file và đảm bảo nó nằm cùng thư mục với script.")
except ConnectionRefusedError:
    print(f"\n[LỖI] Kết nối bị từ chối. Vui lòng đảm bảo server (receiver.py) đang chạy.")
except Exception as e:
    print(f"\n[LỖI KHÔNG XÁC ĐỊNH] Đã có lỗi xảy ra: {e}")