
from flask import Flask, request, jsonify
import jwt
import mysql.connector
from mysql.connector import Error
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, urlsafe_b64encode
from functools import wraps
from flask import request, jsonify
import os, json, hashlib
from datetime import datetime
import logging
from decimal import Decimal  # Thêm dòng này để kiểm tra kiểu Decimal
import copy

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def verify_apisix_jwt(token):
    apisix_secret_key = "my-secret-hmac-key"
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

app = Flask(__name__)

DB_CONFIG = {
    'host': 'mysql-db',
    'port': '3307',
    'database': 'tmdt',
    'user': 'dangnosuy',
    'password': 'dangnosuy',
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'ssl_ca': './database_key_cert/ca.pem',
    'ssl_cert': './database_key_cert/client-cert.pem',
    'ssl_key': './database_key_cert/client-key.pem'
}

# Load public key for JWT
with open("./jwt/client_public_key.pem", "rb") as f:
    client_public_key = serialization.load_pem_public_key(f.read()) # load public_key to authentication JWT

# Load private key to sign data
with open("./sign_data/B_private_key.pem", "rb") as f:
    b_private_key = serialization.load_pem_private_key(f.read(), password=None)

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, client_public_key, algorithms=["ES256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def get_db_connection():
    """Tạo kết nối đến database MySQL"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        app.logger.error(f"Error connecting to MySQL: {e}")
        return None


def get_all_customers():
    """Lấy tất cả thông tin khách hàng từ database"""
    connection = get_db_connection()
    if not connection:
        return None, "Database connection failed"
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Truy vấn để lấy thống kê khách hàng
        query = """
        SELECT 
            ROW_NUMBER() OVER (ORDER BY MIN(id)) as customer_id,
            username as name,
            COUNT(*) as orders,
            SUM(quantity) as total_items_purchased,
            SUM(price * quantity) as total_amount_spent,
            MIN(purchase_time) as first_purchase,
            MAX(purchase_time) as last_purchase
        FROM orders 
        GROUP BY username 
        ORDER BY MIN(id)
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Chuyển đổi datetime thành string để JSON serializable
        for result in results:
            if result['first_purchase']:
                result['first_purchase'] = result['first_purchase'].isoformat()
            if result['last_purchase']:
                result['last_purchase'] = result['last_purchase'].isoformat()
            
            # Format số tiền
            result['total_amount_spent'] = float(result['total_amount_spent'])
        
        return results, None
        
    except Error as e:
        app.logger.error(f"Error executing query: {e}")
        return None, f"Database query failed: {str(e)}"
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/all-customers", methods=["GET"])
@require_role("admin")
def all_customers(user_payload):

    customers_data, error = get_all_customers()

    if error:
        app.logger.error(f"Lỗi khi lấy dữ liệu khách hàng: {error}")
        return jsonify({"error": "Không thể lấy dữ liệu khách hàng"}), 500
    
    if not customers_data:
        return jsonify({"error": "Không tìm thấy dữ liệu khách hàng"}), 404
    
    # Sao chép sâu dữ liệu để không ảnh hưởng đến dữ liệu gốc
    payload_data = copy.deepcopy(customers_data)
    
    # Chuyển tất cả Decimal thành float trong payload_data
    for customer in payload_data:
        for key, value in customer.items():
            if isinstance(value, Decimal):
                customer[key] = float(value)
    
    # Tạo payload để mã hóa JWT
    
    data_str = json.dumps(payload_data, separators=(',', ':'), ensure_ascii=False)
    data_hash = hashlib.sha256(data_str.encode()).digest()
    data_hash_b64 = urlsafe_b64encode(data_hash).decode()
    app.logger.info(f"Hash data: {data_hash}")
    payload = {
        "customers": data_hash_b64,
        "timestamp": datetime.utcnow().isoformat(),
        "total_customers": len(customers_data)
    }
    # Mã hóa payload với JWT
    signature = jwt.encode(payload, b_private_key, algorithm="ES256")
    app.logger.info(f"Chữ ký: {signature}")
    return jsonify({
        "data": customers_data,
        "total_customers": len(customers_data),
        "payload" : payload,
        "signature": signature
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=True)
