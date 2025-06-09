from flask import Flask, request, jsonify
import hashlib, re
import mysql.connector
from mysql.connector import Error
import jwt, random
import datetime
from functools import wraps
from cryptography.hazmat.primitives import serialization
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
    
def verify_jwt(token):
    try:
        decoded = jwt.decode(token, client_public_key, algorithms=["ES256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
    
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
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = 'user' 

    if len(username) < 8:
        return jsonify({"error" : "Length of username least 8 character!"}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character"}), 400

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_pw = hash_password(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Kiểm tra username đã tồn tại
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Username already exists"}), 409
        # Chèn người dùng mới
        cursor.execute(
            "INSERT INTO users (username, hashed_password, role) VALUES (%s, %s, %s)",
            (username, hashed_pw, role)
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
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # Chữ hoa
        return False
    if not re.search(r"[a-z]", password):  # Chữ thường
        return False
    if not re.search(r"[0-9]", password):  # Số
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Ký tự đặc biệt
        return False
    return True

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minutes")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = hash_password(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, role FROM users WHERE username=%s AND hashed_password=%s", (username, hashed_pw))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid username or password"}), 401
        
        user_id, role = user
        jti = str(random.randint(0, 100000))
        
        cursor.execute("SELECT * FROM blacklist WHERE username=%s", (username, ))
        blacklist = cursor.fetchone()

        if not blacklist:
            cursor.execute("INSERT INTO blacklist (username, jti) VALUES (%s, %s)", (username, jti))
        else:
            cursor.execute("UPDATE blacklist SET jti=%s WHERE username=%s", (jti, username))

        conn.commit()
        # Tạo payload cho JWT
        payload = {
            "sub": username,
            "role": role,
            "jti" : str(jti),
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }

        # Tạo JWT với ES256 (ECDSA + SHA256)
        token = jwt.encode(
            payload,
            private_key,
            algorithm="ES256"
        )
        
        return jsonify({"access_token": token})

    except Exception as e:
        print("Login error:", e)
        return jsonify({"error": "Internal server error"}), 500

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            

@app.route('/update-permision', methods=['POST'])
@require_role("admin")
def update_permision(user_payload):
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
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=('./ssl_cert/ecdsa_cert.pem', './ssl_cert/ecdsa_key.pem'))
