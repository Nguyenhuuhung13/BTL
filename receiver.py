# receiver.py (Đã sửa lỗi)
import socket
import json
import base64
import time
from datetime import datetime, timezone
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad
import os

# --- Cấu hình Server ---
HOST = '127.0.0.1'
PORT = 65432
BUFFER_SIZE = 4096

# --- Tạo và lưu khóa của Người Nhận ---
print("--- Phía Người Nhận (Server) ---")
print("Đang tạo cặp khóa RSA 2048-bit cho Người Nhận...")
receiver_key = RSA.generate(2048)

with open("receiver_private.pem", "wb") as f:
    f.write(receiver_key.export_key())
with open("receiver_public.pem", "wb") as f:
    f.write(receiver_key.publickey().export_key())
print("Đã tạo và lưu khóa của Người Nhận vào file receiver_private.pem và receiver_public.pem")

# Biến toàn cục để lưu khóa công khai của người gửi
sender_public_key = None

def load_sender_public_key():
    """Hàm để nạp khóa công khai của người gửi"""
    global sender_public_key
    try:
        with open("sender_public.pem", "rb") as f:
            sender_public_key = RSA.import_key(f.read())
        print("Đã nạp khóa công khai của Người Gửi (sender_public.pem) để xác thực.")
        return True
    except FileNotFoundError:
        print("[LƯU Ý] Không tìm thấy file sender_public.pem. File này sẽ được tạo khi sender.py chạy lần đầu.")
        return False


def verify_and_decrypt(data_packet):
    """
    Hàm xác thực và giải mã gói tin nhận được
    """
    global sender_public_key

    if not sender_public_key:
        if not load_sender_public_key():
            # SỬA LỖI: Thêm None để đủ 3 giá trị
            return None, "NACK (Sender public key not found)", None

    try:
        # 1. Tách và decode dữ liệu từ gói tin JSON
        iv = base64.b64decode(data_packet['iv'])
        ciphertext = base64.b64decode(data_packet['cipher'])
        hash_hex = data_packet['hash']
        signature = base64.b64decode(data_packet['sig'])
        exp_iso = data_packet['exp']
        encrypted_session_key = base64.b64decode(data_packet['session_key'])
        metadata_b64 = data_packet['metadata']
        metadata = base64.b64decode(metadata_b64)

        # 2. Kiểm tra thời hạn (expiration)
        print(f"\n[BƯỚC 4.1] Kiểm tra thời hạn... (Hết hạn lúc: {exp_iso})")
        exp_time = datetime.fromisoformat(exp_iso.replace('Z', '+00:00'))
        if datetime.now(timezone.utc) > exp_time:
            print("[LỖI] Gói tin đã hết hạn.")
            # SỬA LỖI: Thêm None để đủ 3 giá trị
            return None, "NACK (Timeout)", None
        print(" -> Thời hạn hợp lệ.")

        # 3. Kiểm tra tính toàn vẹn (hash)
        print("[BƯỚC 4.2] Kiểm tra tính toàn vẹn (SHA-512)...")
        hash_payload = iv + ciphertext + exp_iso.encode('utf-8')
        h = SHA512.new(hash_payload)
        if h.hexdigest() != hash_hex:
            print("[LỖI] Hash không khớp. Dữ liệu có thể đã bị thay đổi.")
            # SỬA LỖI: Thêm None để đủ 3 giá trị
            return None, "NACK (Integrity)", None
        print(" -> Hash hợp lệ. Dữ liệu toàn vẹn.")

        # 4. Kiểm tra chữ ký (authentication)
        print("[BƯỚC 4.3] Kiểm tra chữ ký (RSA/SHA-512)...")
        h_meta = SHA512.new(metadata)
        pkcs1_15.new(sender_public_key).verify(h_meta, signature)
        # pkcs1_15.new(receiver_key).verify(h_meta, signature) # mô phỏng lỗi xác thực

        print(" -> Chữ ký hợp lệ. Người gửi đã được xác thực.")

        # 5. Giải mã SessionKey bằng Private Key của Người Nhận
        print("[BƯỚC 4.4] Giải mã Session Key...")
        cipher_rsa = PKCS1_v1_5.new(receiver_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key, b'DECRYPTION FAILED')
        if session_key == b'DECRYPTION FAILED':
            print("[LỖI] Giải mã session key thất bại.")
            # SỬA LỖI: Thêm None để đủ 3 giá trị
            return None, "NACK (Session Key Decryption)", None
        print(" -> Đã giải mã thành công Session Key.")

        # 6. Giải mã dữ liệu file bằng AES-CBC
        print("[BƯỚC 4.5] Giải mã dữ liệu file bằng AES-CBC...")
        # Bắt đầu tính thời gian giải mã TẠI ĐÂY
        start_time = time.time()
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_data_padded = cipher_aes.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_data_padded, AES.block_size)
        # Kết thúc tính thời gian giải mã TẠI ĐÂY
        end_time = time.time()
        decryption_time = end_time - start_time
        print(f" -> Giải mã file thành công. (Thời gian giải mã: {decryption_time:.6f} giây)")



        # Trích xuất tên file từ metadata
        metadata_str = metadata.decode('utf-8')
        filename = metadata_str.split(',')[0].split(':')[1].strip()

        # Đây là trường hợp thành công, đã trả về 3 giá trị đúng
        return decrypted_data, "ACK (Success)", filename

    except (ValueError, TypeError) as e:
        print(f"[LỖI] Xác thực hoặc giải mã thất bại: {e}")
        # Chỗ này đã trả về 3 giá trị đúng
        return None, "NACK (Verification/Decryption Error)", None
    except Exception as e:
        print(f"[LỖI HỆ THỐNG] Lỗi không xác định: {e}")
        # Chỗ này đã trả về 3 giá trị đúng
        return None, f"NACK (Error: {e})", None

# --- Main Server Logic ---
load_sender_public_key() # Cố gắng nạp key khi khởi động

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"\nServer đang lắng nghe tại {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"Đã kết nối bởi {addr}")

        # Bước 1: Handshake
        msg = conn.recv(BUFFER_SIZE).decode()
        if msg == "Hello!":
            conn.sendall(b"Ready!")
        else:
            conn.close()
            exit() # Thoát nếu handshake không đúng

        # Bước 2: Gửi public key của receiver
        conn.sendall(receiver_key.publickey().export_key())

        # Bước 4: Nhận gói tin
        full_data = b''
        while True:
            part = conn.recv(BUFFER_SIZE)
            if not part:
                break
            full_data += part
            if len(part) < BUFFER_SIZE:
                break

        data_packet_json = json.loads(full_data.decode('utf-8'))
        decrypted_data, status, received_filename = verify_and_decrypt(data_packet_json)

        # Lưu file nếu giải mã thành công
        if decrypted_data and received_filename:
            saved_filename = f"DECRYPTED_{received_filename}"
            with open(saved_filename, "wb") as f:
                f.write(decrypted_data)
            print(f"\n[HOÀN TẤT] Dữ liệu đã được giải mã và lưu vào file '{saved_filename}'")

        conn.sendall(status.encode('utf-8'))
        print(f"Đã gửi phản hồi '{status}' cho Người Gửi.")
