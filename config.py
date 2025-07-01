from Crypto.PublicKey import RSA

def load_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

# Load khóa người gửi
SENDER_PRIVATE_KEY = load_key("sender_private.pem")
SENDER_PUBLIC_KEY = load_key("sender_public.pem")

# Load khóa người nhận
RECEIVER_PRIVATE_KEY = load_key("receiver_private.pem")
RECEIVER_PUBLIC_KEY = load_key("receiver_public.pem")

# Khóa phiên (session key) cho Triple DES: 24 bytes
SESSION_KEY = b'123456789012345678901234'  # Bạn có thể thay bằng khóa ngẫu nhiên khác
