import sys
# Đảm bảo đầu ra console sử dụng UTF-8 để hiển thị ký tự tiếng Việt
sys.stdout.reconfigure(encoding='utf-8')

import os
import base64
import json
from datetime import datetime, UTC # Import UTC cho thời gian nhận biết múi giờ
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from crypto_utils import (
    split_file, encrypt_des3_with_iv, rsa_encrypt, sha512_hash, rsa_sign, rsa_decrypt
)
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
# Đảm bảo các khóa được import đúng cách từ config.py
from config import RECEIVER_PUBLIC_KEY, SENDER_PRIVATE_KEY, RECEIVER_PRIVATE_KEY, SENDER_PUBLIC_KEY

app = Flask(__name__, static_folder='static', template_folder='templates')
# Cấu hình SocketIO để cho phép kết nối từ mọi nguồn (cần cho môi trường phát triển)
socketio = SocketIO(app, cors_allowed_origins="*")

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
# Đảm bảo thư mục 'uploads' tồn tại. Nếu không, tạo nó.
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
print(f'[SERVER START] Thư mục tải lên được thiết lập: {UPLOAD_FOLDER}')

# Biến toàn cục để lưu trữ thông tin session của file đang được xử lý
sessions = {}
# Lưu trữ danh sách các SID của client đang là người nhận (để gửi khóa công khai)
connected_receiver_sids = set() 
print('[SERVER START] Biến sessions và connected_receiver_sids được khởi tạo.')

# --- Định nghĩa các Route cho Flask ---
@app.route('/')
def server_page():
    print('[REQUEST] Truy cập trang chủ server.')
    return render_template('server.html')

@app.route('/sender')
def sender_page():
    print('[REQUEST] Truy cập trang Người Gửi.')
    return render_template('sender.html')

@app.route('/receiver')
def receiver_page():
    print('[REQUEST] Truy cập trang Người Nhận.')
    return render_template('receiver.html')

# --- Xử lý việc tải file lên từ người gửi (HTTP POST) ---
@app.route('/upload', methods=['POST'])
def upload_file():
    print('[UPLOAD PROCESS] Bắt đầu xử lý yêu cầu tải file lên.')
    print(f'[UPLOAD DEBUG] Nội dung request.form: {request.form}') 

    if 'file' not in request.files:
        print('[UPLOAD ERROR] Lỗi: Không tìm thấy trường "file" trong request.')
        return 'Không tìm thấy file', 400
    file = request.files['file']
    print(f'[UPLOAD INFO] Đã nhận file từ request: {file.filename}')
    
    if not file.filename.endswith('.mp3'):
        print(f'[UPLOAD ERROR] Lỗi: File "{file.filename}" không phải định dạng mp3.')
        return 'Chỉ chấp nhận file mp3', 400

    receiver_public_key_pem_from_sender = request.form.get('receiver_public_key_pem')
    if not receiver_public_key_pem_from_sender:
        print('[UPLOAD ERROR] Lỗi: Không tìm thấy khóa công khai người nhận được gửi từ người gửi.')
        return 'Không tìm thấy khóa công khai người nhận từ người gửi', 400
    print('[UPLOAD INFO] Đã nhận khóa công khai người nhận từ form.')

    sender_socket_id = request.form.get('sender_socket_id') 
    if not sender_socket_id:
        print('[UPLOAD ERROR] Lỗi: Không tìm thấy SocketIO SID của người gửi trong form data.')
        return 'Không tìm thấy SID của người gửi', 400
    print(f'[UPLOAD INFO] Đã nhận SocketIO SID của người gửi từ form: {sender_socket_id}')

    try:
        receiver_public_key_from_sender = RSA.import_key(receiver_public_key_pem_from_sender)
        print('[UPLOAD SUCCESS] Đã parse khóa công khai người nhận thành công.')
    except ValueError as e:
        print(f'[UPLOAD ERROR] Lỗi khi parse khóa công khai người nhận: {e}')
        return f'Khóa công khai người nhận không hợp lệ: {e}', 400

    filename_to_save = 'recording.mp3'
    path_to_save = os.path.join(UPLOAD_FOLDER, filename_to_save)
    
    print(f'[UPLOAD INFO] Đang cố gắng lưu file vào: {path_to_save}')
    try:
        file.save(path_to_save)
        print(f'[UPLOAD SUCCESS] Đã lưu file "{filename_to_save}" thành công vào: {path_to_save}')
    except Exception as e:
        print(f'[UPLOAD CRITICAL ERROR] Lỗi khi lưu file: {e}')
        return f'Lỗi server khi lưu file: {e}', 500

    session_key = get_random_bytes(24)
    print(f'[UPLOAD INFO] Đã tạo session key ngẫu nhiên ({len(session_key)} bytes).')

    try:
        with open(path_to_save, 'rb') as f:
            filedata = f.read()
        print(f'[UPLOAD INFO] Đã đọc file có kích thước {len(filedata)} bytes vào bộ nhớ.')
    except Exception as e:
        print(f'[UPLOAD CRITICAL ERROR] Lỗi khi đọc file đã lưu: {e}')
        return f'Lỗi server khi đọc file đã lưu: {e}', 500

    chunks = split_file(filedata, parts=3)
    print(f'[UPLOAD INFO] File đã được chia thành {len(chunks)} đoạn.')

    sessions['current'] = {
        'filename': filename_to_save,
        'chunks': chunks,
        'session_key': session_key,
        'sent_chunks': 0,
        'size': len(filedata),
        'timestamp': datetime.now(UTC).isoformat() + 'Z',
        'status': 'waiting',
        'receiver_public_key_from_sender': receiver_public_key_from_sender,
        'sender_client_sid': sender_socket_id
    }
    print('[UPLOAD SUCCESS] Thông tin session đã được lưu trữ thành công.')

    print(f'[UPLOAD PROCESS] Hoàn tất xử lý tải lên cho file "{filename_to_save}".')
    return 'Upload thành công, đang chờ gửi file...'

# --- SocketIO Events ---

@socketio.on('connect')
def handle_connect():
    print(f'[SOCKETIO CONNECT] Client mới kết nối: SID="{request.sid}"')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'[SOCKETIO DISCONNECT] Client ngắt kết nối: SID="{request.sid}"')
    # Xóa SID khỏi danh sách người nhận nếu họ ngắt kết nối
    if request.sid in connected_receiver_sids:
        connected_receiver_sids.remove(request.sid)
        print(f'[RECEIVER REMOVED] Đã xóa SID="{request.sid}" khỏi danh sách người nhận.')

@socketio.on('handshake')
def handle_handshake(data):
    msg = data.get('msg')
    print(f"[HANDSHAKE RECEIVE] Người gửi (SID={request.sid}) nói: '{msg}'")
    if msg == 'Hello!':
        emit('handshake_reply', {'msg': 'Ready!'})
        print(f"[HANDSHAKE SEND] Đã gửi 'Ready!' cho người gửi (SID={request.sid}).")

        # GỬI KHÓA CÔNG KHAI NGƯỜI GỬI ĐẾN TẤT CẢ NGƯỜI NHẬN ĐANG TRỰC TUYẾN TẠI ĐÂY
        # (Chỉ khi người gửi đã tải lên file và bắt đầu handshake)
        sender_public_key_pem = SENDER_PRIVATE_KEY.publickey().export_key().decode()
        if connected_receiver_sids:
            print(f"[KEY EXCHANGE] Người gửi đã bắt đầu handshake. Gửi khóa công khai người gửi đến {len(connected_receiver_sids)} người nhận...")
            for receiver_sid in list(connected_receiver_sids): # Dùng list để tránh lỗi thay đổi set khi lặp
                emit('sender_public_key', {'key': sender_public_key_pem}, room=receiver_sid)
                print(f"[KEY EXCHANGE] Đã gửi khóa công khai người gửi đến SID='{receiver_sid}'.") # Fixed syntax
        else:
            print("[KEY EXCHANGE] Không có người nhận nào đang trực tuyến để gửi khóa công khai.")
    else:
        print(f"[HANDSHAKE WARNING] Nhận thông báo handshake không mong muốn: '{msg}'")

@socketio.on('receiver_ready')
def handle_receiver_ready():
    # Khi người nhận sẵn sàng, thêm SID của họ vào danh sách
    connected_receiver_sids.add(request.sid)
    print(f"[RECEIVER READY] Người nhận (SID={request.sid}) đã sẵn sàng và được thêm vào danh sách.")
    # KHÔNG GỬI KHÓA CÔNG KHAI NGƯỜI GỬI NGAY TẠY ĐÂY NỮA

@socketio.on('public_key_confirm')
def handle_public_key_confirm(data):
    status_confirmation = data.get('status')
    current_receiver_sid = request.sid
    print(f"[KEY CONFIRMATION] Người nhận (SID={current_receiver_sid}) xác nhận khóa: '{status_confirmation}'")

    if status_confirmation == 'ok':
        print("[FILE SEND PROCESS] Người nhận xác nhận khóa đúng, chuẩn bị gửi file.")
        session = sessions.get('current')
        if not session:
            print('[FILE SEND ERROR] Lỗi: Không có session đang hoạt động khi người nhận xác nhận khóa.')
            emit('send_cancel', {'reason': 'Không có session đang hoạt động'}, room=current_receiver_sid) # Gửi riêng cho người nhận này
            return

        # 1. Gửi metadata của file và chữ ký số metadata
        meta = {
            'filename': session['filename'],
            'timestamp': session['timestamp'],
            'duration': 0
        }
        meta_json = json.dumps(meta).encode('utf-8')
        sig = rsa_sign(meta_json, SENDER_PRIVATE_KEY)

        emit('meta', {
            'meta': meta,
            'signature': base64.b64encode(sig).decode()
        }, room=current_receiver_sid) # Gửi riêng cho người nhận này
        print(f"[FILE SEND INFO] Đã gửi metadata và chữ ký đến SID='{current_receiver_sid}'.") # Fixed syntax

        # 2. Mã hóa khóa phiên (session_key) bằng khóa công khai của người nhận
        # KHÓA CÔNG KHAI NGƯỜI NHẬN được lấy từ thông tin do NGƯỜI GỬI cung cấp khi upload file
        enc_session_key = rsa_encrypt(session['session_key'], session['receiver_public_key_from_sender'])
        emit('key', {
            'enc_key': base64.b64encode(enc_session_key).decode()
        }, room=current_receiver_sid) # Gửi riêng cho người nhận này
        print(f"[FILE SEND INFO] Đã gửi khóa phiên đã mã hóa đến SID='{current_receiver_sid}'.") # Fixed syntax

        # 3. Giải mã khóa phiên trên server và gửi nó về cho người nhận
        try:
            # Lưu ý: RECEIVER_PRIVATE_KEY phải tương ứng với khóa công khai mà người gửi đã dùng để server mã hóa
            decrypted_session_key_on_server = rsa_decrypt(enc_session_key, RECEIVER_PRIVATE_KEY)
            emit('decrypted_session_key', {
                'key': base64.b64encode(decrypted_session_key_on_server).decode()
            }, room=current_receiver_sid) # Gửi riêng cho người nhận này
            print(f"[FILE SEND INFO] Đã gửi khóa phiên đã GIẢI MÃ về cho SID='{current_receiver_sid}'.") # Fixed syntax
        except Exception as e:
            print(f"[FILE SEND ERROR] Lỗi khi giải mã khóa phiên trên server: {e}. Vui lòng kiểm tra config.RECEIVER_PRIVATE_KEY và khóa công khai người gửi đã cung cấp.")
            emit('send_cancel', {'reason': f'Lỗi nội bộ server khi giải mã khóa phiên: {e}'}, room=current_receiver_sid)
            return

        # 4. Gửi từng đoạn file đã được mã hóa
        num_chunks = len(session['chunks'])
        for i, chunk_data in enumerate(session['chunks']):
            iv = get_random_bytes(8)
            encrypted_chunk = encrypt_des3_with_iv(chunk_data, session['session_key'], iv)
            
            hash_of_chunk = sha512_hash(iv + encrypted_chunk)
            sig_of_chunk = rsa_sign(hash_of_chunk, SENDER_PRIVATE_KEY)

            emit('chunk', {
                'index': i,
                'iv': base64.b64encode(iv).decode(),
                'cipher': base64.b64encode(encrypted_chunk).decode(),
                'hash': base64.b64encode(hash_of_chunk).decode(),
                'sig': base64.b64encode(sig_of_chunk).decode()
            }, room=current_receiver_sid) # Gửi riêng cho người nhận này
            print(f"[FILE SEND PROGRESS] Đã gửi đoạn {i+1}/{num_chunks} đến SID='{current_receiver_sid}'.") # Fixed syntax

        # 5. Gửi tín hiệu kết thúc quá trình gửi file
        emit('end', room=current_receiver_sid) # Gửi riêng cho người nhận này
        print(f"[FILE SEND SUCCESS] Đã gửi xong toàn bộ file đến SID='{current_receiver_sid}'.") # Fixed syntax

        # 6. Gửi thông tin chi tiết file đã chuyển giao thành công tới trang quản lý server
        transfer_info = {
            'filename': session['filename'],
            'original_size_bytes': session['size'],
            'upload_timestamp': session['timestamp'],
            'session_key_hex': session['session_key'].hex(),
            'sender_client_sid': session['sender_client_sid'],
            'receiver_client_sid': current_receiver_sid,
            'status': 'Hoàn thành',
            'num_chunks': num_chunks, 
            'receiver_public_key_snippet': session['receiver_public_key_from_sender'].export_key().decode('utf-8')[27:52] 
        }
        socketio.emit('transfer_complete_details', transfer_info) 
        print("[SERVER LOG] Đã phát sự kiện 'transfer_complete_details' cho trang quản lý.")

        # 7. Xóa session hiện tại sau khi hoàn tất gửi file
        if 'current' in sessions: # Kiểm tra trước khi xóa để tránh lỗi
            del sessions['current']
            print("[SERVER LOG] Đã xóa session hiện tại sau khi gửi file hoàn tất.")

    else:
        print("[FILE SEND CANCEL] Người nhận xác nhận khóa sai. Dừng gửi.")
        emit('send_cancel', {'reason': 'Khóa xác nhận sai'}, room=current_receiver_sid)

# Khởi chạy ứng dụng Flask SocketIO
if __name__ == '__main__':
    print('[SERVER START] Đang khởi động Flask SocketIO server...')
    print(f'[SERVER START] Server sẽ chạy trên http://{os.environ.get("FLASK_RUN_HOST", "0.0.0.0")}:{os.environ.get("FLASK_RUN_PORT", "8080")}')
    socketio.run(app, port=8080, debug=True, allow_unsafe_werkzeug=True)
