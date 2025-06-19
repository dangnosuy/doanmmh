from flask import Flask, request, jsonify
import mysql.connector
import jwt, json
from cryptography.hazmat.primitives import serialization
import requests, hashlib
from functools import wraps
from decimal import Decimal  # Thêm dòng này để kiểm tra kiểu Decimal
import copy
from base64 import b64encode, urlsafe_b64encode
from datetime import datetime

app = Flask(__name__)

# Load keys
with open("./jwt/client_public_key.pem", "rb") as f:
    client_public_key = serialization.load_pem_public_key(f.read())

# DB config
DB_CONFIG = {
    'host': 'mysql-db',
    'port': '3306',
    'user': 'dangnosuy',
    'password': 'dangnosuy',
    'database': 'tmdt',
    'ssl_ca': './database_key_cert/ca.pem',
    'ssl_cert': './database_key_cert/client-cert.pem',
    'ssl_key': './database_key_cert/client-key.pem'
}
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
            app.logger.info(f"payload: {payload}")
            if "error" in payload:
                return jsonify(payload), 401

            user_role = payload.get("role")
            if user_role not in allowed_roles:
                return jsonify({"error": "Permission denied"}), 403

            # Inject payload vào kwargs để dùng bên trong route nếu muốn
            return f(*args, **kwargs, user_payload=payload)
        return wrapper
    return decorator

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# JWT verification
def verify_jwt(token):
    try:
        decoded = jwt.decode(token, client_public_key, algorithms=["ES256"])
        username = decoded['sub']
        jti = decoded['jti']
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT 1 FROM blacklist WHERE username=%s AND jti=%s", (username, jti))
            check = cursor.fetchone()
            if not check:
                return {"error": "Token has changed"}
        except Exception as e:
            return {"error" : str(e)}
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

with open("./sign_data/A_private_key.pem", "rb") as f:
    a_private_key = serialization.load_pem_private_key(f.read(), password=None)

@app.route("/products", methods=["GET"])
@require_role("admin", "user")
@require_apisix_jwt()
def get_products(user_payload, apisix_payload):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, product_name, price, quantity_available FROM products")
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    if not products:
        return jsonify({"error": "No products found"}), 404

    # Deep copy để không ảnh hưởng dữ liệu gốc
    payload_data = copy.deepcopy(products)

    # Chuyển Decimal (nếu có) thành float
    for product in payload_data:
        for key, value in product.items():
            if isinstance(value, Decimal):
                product[key] = float(value)

    # Mã hóa JSON rồi hash
    data_str = json.dumps(payload_data, separators=(',', ':'), ensure_ascii=False)
    data_hash = hashlib.sha256(data_str.encode()).digest()
    data_hash_b64 = urlsafe_b64encode(data_hash).decode()

    # Tạo payload để ký
    payload = {
        "products_hash": data_hash_b64,
        "timestamp": datetime.utcnow().isoformat(),
        "total_products": len(payload_data)
    }

    # Ký payload bằng private key của microservice A
    signature = jwt.encode(payload, a_private_key, algorithm="ES256")

    return jsonify({
        "data": products,
        "total_products": len(products),
        "signature": signature,
        "payload": payload
    }), 200



@app.route("/top-5-orders", methods=["GET"])
@require_role("admin")
@require_apisix_jwt()
def top_10_order(user_payload, apisix_payload):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 5;")
    data = cursor.fetchall()

    app.logger.info(f"Data: {data}")

    if not data:
        return jsonify({"error": "No orders found"}), 404

    # Deep copy để không ảnh hưởng dữ liệu gốc
    payload_data = copy.deepcopy(data)

    # Chuyển Decimal (nếu có) thành float
    for product in payload_data:
        for key in product:
            if isinstance(product[key], Decimal):
                product[key] = float(product[key])
                
    # Mã hóa JSON rồi hash
    data_str = json.dumps(payload_data, separators=(',', ':'), ensure_ascii=False, default=str)
    data_hash = hashlib.sha256(data_str.encode()).digest()
    data_hash_b64 = urlsafe_b64encode(data_hash).decode()

    # Tạo payload để ký
    payload = {
        "products_hash": data_hash_b64,
        "timestamp": datetime.utcnow().isoformat(),
        "total_products": len(payload_data)
    }

    # Ký payload bằng private key của microservice A
    signature = jwt.encode(payload, a_private_key, algorithm="ES256")

    return jsonify({
        "data": data,
        "signature": signature,
        "payload": payload
    }), 200

@app.route("/order", methods=["POST"])
@require_role("admin", "user")
@require_apisix_jwt()
def order_product(user_payload,apisix_payload):
    data = request.get_json()
    username = user_payload.get("sub")
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))
    #"""use {
    #      product_id: 1,
    #      quantity: 5
    # }"""

    if not product_id or quantity < 1:
        return jsonify({"error": "Invalid product_id or quantity"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Kiểm tra tồn kho
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    if not product:
        return jsonify({"error": "Product not found"}), 404
    if product["quantity_available"] < quantity:
        return jsonify({"error": "Not enough quantity"}), 400

    # Trừ số lượng, ghi đơn hàng
    cursor.execute("UPDATE products SET quantity_available = quantity_available - %s WHERE id = %s", (quantity, product_id))
    cursor.execute("""
        INSERT INTO orders (username, product_name, price, quantity)
        VALUES (%s, %s, %s, %s)
    """, (username, product["product_name"], product["price"], quantity))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "message": f"Order placed successfully for '{product['product_name']}' (x{quantity})"
    }), 200

@app.route("/update-product", methods=["POST"])
@require_role("admin")
@require_apisix_jwt()
def update_product(user_payload, apisix_payload):
    data = request.get_json()
    #use {product_id : 1, product_name: abcde, price : 808008, quantity: 5}
    # thường sẽ dùng update tên, giá, và số lượng
    product_id = data.get('product_id') # bắt buộc có
    name = data.get('product_name')
    price = data.get('price')
    quantity = data.get('quantity')

    if not id:
        return jsonify({
            "error" : "Invalid ID product"
        }), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if name:
            cursor.execute("UPDATE products SET product_name=%s WHERE id=%s", (name, product_id))
        
        if price:
            cursor.execute("UPDATE products SET price=%s WHERE id=%s", (price, product_id))

        if quantity:
            cursor.execute("UPDATE products SET quantity_available=%s WHERE id=%s", (quantity, product_id))

        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        app.log_exception(f"Error: {e}")
        return jsonify({"error" : str(e)}), 400
    
    return jsonify({
        "message" : "Update data successfully"
    })
    

@app.route("/add-product", methods=["POST"])
@require_role("admin")
@require_apisix_jwt()
def add_product(user_payload, apisix_payload):
    data = request.get_json()
    name = data.get("product_name")
    price = data.get("price")
    quantity_available = data.get("quantity")

    if not name or not price:
        return jsonify({
            "error" : "Missing data"
        }), 400

    if not quantity_available:
        quantity_available = 0
    
    try:
        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (product_name, price, quantity_available) VALUES (%s, %s, %s)", (name, price, quantity_available))
        
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        app.log_exception(f"Error: {e}")
        return jsonify({
            "error" : str(e)
        }), 400
    
    return jsonify({
        "message" : "Add product succesfully"
    })

@app.route("/delete-product", methods=["POST"])
@require_role("admin")
@require_apisix_jwt()
def delete_product(user_payload, apisix_payload):
    data = request.get_json()
    id = data.get('product_id')

    if not id:
        return jsonify({
            "error" : "Invalid to delete product"
        })
    
    try:
        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id=%s", (id, ))
        
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        app.log_exception(f"Error: {e}")
        return jsonify({
            "error" : str(e)
        })
    
    return jsonify({
        "message" : "Delete product succesfully"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000, debug=True)
