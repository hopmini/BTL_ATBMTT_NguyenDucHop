import sys
# Đảm bảo đầu ra console sử dụng UTF-8 để hiển thị ký tự tiếng Việt
sys.stdout.reconfigure(encoding='utf-8')

import os
import base64
import json
from datetime import datetime, UTC
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from crypto_utils import (
    split_file, encrypt_des3_with_iv, rsa_encrypt, sha512_hash, rsa_sign, rsa_decrypt
)
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from config import RECEIVER_PUBLIC_KEY, SENDER_PRIVATE_KEY, RECEIVER_PRIVATE_KEY, SENDER_PUBLIC_KEY

app = Flask(__name__, static_folder='static', template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*")

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sessions = {}
connected_receiver_sids = set()

@app.route('/')
def server_page():
    return render_template('server.html')

@app.route('/sender')
def sender_page():
    return render_template('sender.html')

@app.route('/receiver')
def receiver_page():
    return render_template('receiver.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'Không tìm thấy file', 400
    file = request.files['file']
    if not file.filename.endswith('.mp3'):
        return 'Chỉ chấp nhận file mp3', 400

    receiver_public_key_pem_from_sender = request.form.get('receiver_public_key_pem')
    if not receiver_public_key_pem_from_sender:
        socketio.emit('error_log', 'Không tìm thấy khóa công khai người nhận')
        return 'Không tìm thấy khóa công khai người nhận từ người gửi', 400

    sender_socket_id = request.form.get('sender_socket_id') 
    if not sender_socket_id:
        return 'Không tìm thấy SID của người gửi', 400

    try:
        receiver_public_key_from_sender = RSA.import_key(receiver_public_key_pem_from_sender)
    except ValueError as e:
        socketio.emit('error_log', f'Lỗi parse khóa người nhận: {e}')
        return f'Khóa công khai người nhận không hợp lệ: {e}', 400

    filename_to_save = 'recording.mp3'
    path_to_save = os.path.join(UPLOAD_FOLDER, filename_to_save)
    try:
        file.save(path_to_save)
    except Exception as e:
        socketio.emit('error_log', f'Lỗi lưu file: {e}')
        return f'Lỗi server khi lưu file: {e}', 500

    session_key = get_random_bytes(24)
    try:
        with open(path_to_save, 'rb') as f:
            filedata = f.read()
    except Exception as e:
        socketio.emit('error_log', f'Lỗi đọc file: {e}')
        return f'Lỗi server khi đọc file đã lưu: {e}', 500

    # Chia file thành 3 đoạn
    chunks = split_file(filedata, parts=3)
    sessions['current'] = {
        'filename': filename_to_save,
        'chunks': chunks,
        'session_key': session_key,
        'sent_chunks_count': 0, # Đổi tên thành sent_chunks_count để tránh nhầm lẫn
        'size': len(filedata),
        'timestamp': datetime.now(UTC).isoformat() + 'Z',
        'status': 'waiting',
        'receiver_public_key_from_sender': receiver_public_key_from_sender,
        'sender_client_sid': sender_socket_id
    }
    socketio.emit('session_update', 'Đang hoạt động')
    return 'Upload thành công, đang chờ gửi file...'

@socketio.on('connect')
def handle_connect():
    emit('connect')

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in connected_receiver_sids:
        connected_receiver_sids.remove(request.sid)
        socketio.emit('receiver_disconnected')
    # Nếu người gửi ngắt kết nối khi đang trong phiên, hủy phiên
    if 'current' in sessions and sessions['current']['sender_client_sid'] == request.sid:
        socketio.emit('send_cancel', {'reason': 'Người gửi đã ngắt kết nối.'}, room=request.sid)
        if 'current' in sessions: # Kiểm tra lại để tránh KeyError nếu đã bị xóa
            del sessions['current']
        socketio.emit('session_update', 'Không')


@socketio.on('handshake')
def handle_handshake(data):
    msg = data.get('msg')
    if msg == 'Hello!':
        emit('handshake_reply', {'msg': 'Ready!'})
        sender_public_key_pem = SENDER_PRIVATE_KEY.publickey().export_key().decode()
        for receiver_sid in list(connected_receiver_sids):
            emit('sender_public_key', {'key': sender_public_key_pem}, room=receiver_sid)

@socketio.on('receiver_ready')
def handle_receiver_ready():
    connected_receiver_sids.add(request.sid)
    socketio.emit('receiver_connected')

@socketio.on('public_key_confirm')
def handle_public_key_confirm(data):
    if data.get('status') != 'ok':
        emit('send_cancel', {'reason': 'Khóa xác nhận sai'})
        return

    session = sessions.get('current')
    if not session:
        emit('send_cancel', {'reason': 'Không có session đang hoạt động'})
        return

    current_receiver_sid = request.sid
    # Lưu SID của người nhận vào session
    session['receiver_client_sid'] = current_receiver_sid
    session['status'] = 'key_exchange_complete' # Cập nhật trạng thái

    meta = {
        'filename': session['filename'],
        'timestamp': session['timestamp'],
        'duration': 0, # Giá trị này có thể được cập nhật sau nếu cần
        'num_chunks': len(session['chunks']) # Thêm số lượng chunks vào metadata
    }
    meta_json = json.dumps(meta).encode('utf-8')
    sig = rsa_sign(meta_json, SENDER_PRIVATE_KEY)
    emit('meta', {
        'meta': meta,
        'signature': base64.b64encode(sig).decode()
    }, room=current_receiver_sid)

    enc_session_key = rsa_encrypt(session['session_key'], session['receiver_public_key_from_sender'])
    emit('key', {
        'enc_key': base64.b64encode(enc_session_key).decode()
    }, room=current_receiver_sid)

    try:
        # Giải mã khóa phiên trên server để xác nhận (có thể bỏ qua bước này nếu không cần thiết)
        decrypted_session_key_on_server = rsa_decrypt(enc_session_key, RECEIVER_PRIVATE_KEY)
        emit('decrypted_session_key', {
            'key': base64.b64encode(decrypted_session_key_on_server).decode()
        }, room=current_receiver_sid)
    except Exception as e:
        socketio.emit('error_log', f'Lỗi giải mã session key trên server: {e}')
        emit('send_cancel', {'reason': f'Lỗi nội bộ server khi giải mã: {e}'}, room=current_receiver_sid)
        return

    # Server chờ yêu cầu từ người nhận, không gửi chunk nào ở đây
    print(f"Người nhận {current_receiver_sid} đã xác nhận khóa. Chờ yêu cầu chunk đầu tiên.")


@socketio.on('request_next_chunk')
def handle_request_next_chunk(data):
    requested_index = data.get('nextIndex')
    current_receiver_sid = request.sid

    session = sessions.get('current')
    if not session or session.get('receiver_client_sid') != current_receiver_sid:
        emit('send_cancel', {'reason': 'Không có session đang hoạt động hoặc session không khớp.'})
        return

    if requested_index is None or not isinstance(requested_index, int):
        emit('send_cancel', {'reason': 'Chỉ số đoạn không hợp lệ.'})
        return

    if requested_index < 0 or requested_index >= len(session['chunks']):
        emit('send_cancel', {'reason': f'Chỉ số đoạn nằm ngoài phạm vi ({requested_index}).'})
        return

    chunk_data = session['chunks'][requested_index]
    session_key = session['session_key']

    try:
        iv = get_random_bytes(8)
        encrypted_chunk = encrypt_des3_with_iv(chunk_data, session_key, iv)
        hash_of_chunk = sha512_hash(iv + encrypted_chunk)
        sig_of_chunk = rsa_sign(hash_of_chunk, SENDER_PRIVATE_KEY)

        emit('chunk', {
            'index': requested_index,
            'iv': base64.b64encode(iv).decode(),
            'cipher': base64.b64encode(encrypted_chunk).decode(),
            'hash': base64.b64encode(hash_of_chunk).decode(),
            'sig': base64.b64encode(sig_of_chunk).decode()
        }, room=current_receiver_sid)

        session['sent_chunks_count'] += 1 # Tăng số lượng đoạn đã gửi
        print(f"Đã gửi đoạn {requested_index + 1}/{len(session['chunks'])} tới người nhận {current_receiver_sid}")

        # Nếu đã gửi hết các đoạn, gửi tín hiệu 'end' và cập nhật trạng thái
        if session['sent_chunks_count'] == len(session['chunks']):
            emit('end', room=current_receiver_sid)
            transfer_info = {
                'filename': session['filename'],
                'original_size_bytes': session['size'],
                'upload_timestamp': session['timestamp'],
                'session_key_hex': session['session_key'].hex(),
                'sender_client_sid': session['sender_client_sid'],
                'receiver_client_sid': current_receiver_sid,
                'status': 'Hoàn thành',
                'num_chunks': len(session['chunks']),
                'receiver_public_key_snippet': session['receiver_public_key_from_sender'].export_key().decode('utf-8')[27:52]
            }
            socketio.emit('transfer_complete_details', transfer_info)
            # Xóa session sau khi hoàn thành
            if 'current' in sessions:
                del sessions['current']
            socketio.emit('session_update', 'Không')

    except Exception as e:
        socketio.emit('error_log', f'Lỗi khi gửi đoạn {requested_index}: {e}')
        emit('send_cancel', {'reason': f'Lỗi server khi xử lý đoạn {requested_index}: {e}'}, room=current_receiver_sid)


if __name__ == '__main__':
    socketio.run(app, port=5050, debug=True, allow_unsafe_werkzeug=True)