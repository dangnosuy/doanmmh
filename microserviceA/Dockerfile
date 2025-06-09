# Sử dụng base image Python chính thức
FROM python:3.11-slim

# Cài các gói hệ thống cần thiết (có thể thiếu nếu chỉ dùng pip)
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Tạo thư mục app
WORKDIR /app

# Copy mã nguồn và requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Lắng nghe trên cổng 5000
EXPOSE 6000

# Lệnh chạy app (giả sử bạn dùng Flask)
CMD ["python", "microserviceA.py"]
