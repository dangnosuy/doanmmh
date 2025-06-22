from flask import Flask, request, jsonify
import hashlib, re
import mysql.connector
from mysql.connector import Error
import jwt, random
from jwt import ExpiredSignatureError, InvalidTokenError
import datetime
from functools import wraps
from cryptography.hazmat.primitives import serialization
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from password_strength import PasswordPolicy
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

with open("./jwt/private_key.pem", "rb") as f:
    private_key_data = f.read()
    private_key = serialization.load_pem_private_key(private_key_data, password=None)
# Kết nối tới MySQL
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='mysql-db',
            port=3306,
            user='root',
            password='dangnosuy',
            database='tmdt',
            ssl_ca='./database_key_cert/ca.pem',
            ssl_cert='./database_key_cert/client-cert.pem',
            ssl_key='./database_key_cert/client-key.pem'
        )
        return conn
    except mysql.connector.Error as err:
        app.log_exception(f"Error database: {err}")
        return None

with open("./jwt/client_public_key.pem", "rb") as f:
    client_public_key = serialization.load_pem_public_key(f.read()) # load public_key to authentication JWT
    
with open("./apisix-key/public_key.pem", "rb") as f:
    apisix_public_key = serialization.load_pem_public_key(f.read())

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, client_public_key, algorithms=["ES256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
    
# Key này phải giống với `key` trong plugin APISIX của bạn
  # ⚠️ Thay thế bằng key thực tế

def verify_apisix_jwt(token):
    apisix_secret_key = "8649b8d14cf53f327521e52012862e927ef74c63ff9baec5a85ff9afb4f0d724"
    try:
        decoded = jwt.decode(
            token,
            apisix_secret_key,
            algorithms=["HS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": False,
                "verify_iss": False,
                "verify_aud": False
            }
            # Không cần `issuer` và `audience` vì plugin không có các trường đó
        )
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError as e:
        return {"error": f"Invalid token: {str(e)}"}

def require_apisix_jwt():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("X-Gateway-JWT")
            print(f"Token: {token}")
            if not token:
                return jsonify({"error": "Missing X-Gateway-JWT header"}), 401

            payload = verify_apisix_jwt(token)
            if "error" in payload:
                return jsonify(payload), 401

            return f(*args, **kwargs, apisix_payload=payload)
        return wrapper
    return decorator
    
def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header.split(" ")[1]
            payload = verify_jwt(token)
            if "error" in payload:
                return jsonify(payload), 401

            user_role = payload.get("role")
            if user_role not in allowed_roles:
                return jsonify({"error": "Permission denied"}), 403

            # Inject payload vào kwargs để dùng bên trong route nếu muốn
            return f(*args, **kwargs, user_payload=payload)
        return wrapper
    return decorator

# Hàm hash mật khẩu SHA-384
def hash_password(password):
    return hashlib.sha384(password.encode()).hexdigest()

@app.route("/register", methods=["POST"])
@require_apisix_jwt()
def register(apisix_payload):
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    role = 'user'

    # Kiểm tra đầu vào
    if not username or not password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400


    if not is_strong_password(password):
        return jsonify({
            "error": "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character"
        }), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    hashed_pw = hash_password(password)

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Kiểm tra username/email đã tồn tại
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return jsonify({"error": "Username or email already exists"}), 409

        # Chèn người dùng mới
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_pw, role)
        )
        conn.commit()

        return jsonify({"message": "User registered successfully"}), 201

    except Error as e:
        print("Database error:", e)
        return jsonify({"error": "Database error"}), 500

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def is_strong_password(password):
    """
    Password mạnh nếu:
    - Ít nhất 8 ký tự
    - Có ít nhất một chữ hoa
    - Có ít nhất một chữ thường
    - Có ít nhất một số
    - Có ít nhất một ký tự đặc biệt
    """
    policy = PasswordPolicy.from_names(
        length = 8,
        uppercase = 1,
        numbers = 1,
        special = 1,
        nonletters = 1
    )
    return len(policy.test(password)) == 0

def send_email(to_email, subject, content):
    from_email = "23520226@gm.uit.edu.vn"         # 🔒 Thay bằng địa chỉ Gmail của bạn
    app_password = "clcj fewb mhxl dxpi"     # 🔒 Dùng App Password, KHÔNG dùng mật khẩu thật

    # Tạo nội dung email
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(content, "plain"))

    try:
        # Kết nối tới Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(from_email, app_password)
            server.send_message(msg)
        print(f"✅ Sent email to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {to_email}. Error: {e}")

@app.route("/login", methods=["POST"])
@require_apisix_jwt()
@limiter.limit("5 per minutes")
def login(apisix_payload):
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = hash_password(password)

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Kiểm tra tài khoản
        cursor.execute("SELECT email FROM users WHERE username=%s AND hashed_password=%s", (username, hashed_pw))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        user_email = user[0]

        # Tạo mã OTP 6 chữ số
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

        # Lưu OTP vào DB (nếu tồn tại thì cập nhật)
        cursor.execute("""
            INSERT INTO otp_codes (username, otp_code, expires_at)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE otp_code=%s, expires_at=%s
        """, (username, otp, expires_at, otp, expires_at))
        conn.commit()

        # Gửi email OTP
        send_email(user_email, "Your OTP Code", f"Your OTP code is: {otp}")

        return jsonify({"message": "OTP has been sent to your email"})

    except Exception as e:
        print("Login error:", e)
        return jsonify({"error": "Internal server error"}), 500

    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route("/verify-otp", methods=["POST"])
@require_apisix_jwt()
def verify_otp(apisix_payload):
    data = request.get_json()
    username = data.get("username")
    otp_input = data.get("otp")

    if not username or not otp_input:
        return jsonify({"error": "Username and OTP required"}), 400

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Lấy OTP từ DB
        cursor.execute("SELECT otp_code, expires_at FROM otp_codes WHERE username=%s", (username,))
        row = cursor.fetchone()

        if not row:
            return jsonify({"error": "No OTP found for this user"}), 400

        otp_code, expires_at = row

        if datetime.datetime.utcnow() > expires_at:
            return jsonify({"error": "OTP expired"}), 400

        if otp_input != otp_code:
            return jsonify({"error": "Invalid OTP"}), 401

        # OTP hợp lệ → tạo token và xóa OTP
        cursor.execute("SELECT role FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        role = user[0]

        jti = uuid.uuid4().hex
        cursor.execute("INSERT INTO blacklist (username, jti) VALUES (%s, %s) ON DUPLICATE KEY UPDATE jti=%s", (username, jti, jti))

        # Xóa OTP sau khi dùng
        cursor.execute("DELETE FROM otp_codes WHERE username=%s", (username,))
        conn.commit()

        payload = {
            "sub": username,
            "role": role,
            "jti": jti,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }

        token = jwt.encode(payload, private_key, algorithm="ES256")
        return jsonify({"access_token": token})

    except Exception as e:
        print("Verify OTP error:", e)
        return jsonify({"error": "Internal server error"}), 500

    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route("/change-password", methods=["POST"])
@require_apisix_jwt()
def change_password(apisix_payload):
    username = request.get_json().get("username")

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE usesrname=%s", (username, ))
        user = cursor.fetchone()
        if not user:
            return jsonify({
                "error" : "Cannot found username!"
            }), 401
        

@app.route("/logout", methods=["POST"])
@require_apisix_jwt()  # Middleware sẽ parse JWT và truyền `apisix_payload`
@require_role("admin", "user")
def logout(apisix_payload, user_payload):
    username = user_payload.get("sub")

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Set jti = NULL (tức là xóa jti) khi người dùng logout
        cursor.execute("UPDATE blacklist SET jti=NULL WHERE username=%s", (username,))
        conn.commit()

        return jsonify({"message": f"User '{username}' logged out successfully."})
    except Exception as e:
        print("Logout error:", e)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/update-permision', methods=['POST'])
@require_apisix_jwt()
@require_role("admin")
def update_permision(user_payload, apisix_payload):
    data = request.get_json()
    username = data.get('username')
    role_change = data.get('role')
    username_admin_pro = 'dangnosuy'
    if username == username_admin_pro:
        return jsonify({
            "error" : "Cannot update role this username"
        }), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("UPDATE users SET role=%s WHERE username=%s", (role_change, username))
        conn.commit()
    except Exception as e:
        app.log_exception(f"Error: {e}")
        return jsonify({"error" : str(e)})
    return jsonify({
        "status" : "Update succesfully",
        "username" : username,
        "new-role" : role_change
    })


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
