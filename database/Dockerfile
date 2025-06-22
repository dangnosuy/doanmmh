FROM mysql:8.0.42

# Copy các file chứng chỉ vào thư mục trong container
COPY ca.pem /etc/mysql/ssl/ca.pem
COPY server-cert.pem /etc/mysql/ssl/server-cert.pem
COPY server-key.pem /etc/mysql/ssl/server-key.pem

# Chmod cho các file private key
RUN chown mysql:mysql /etc/mysql/ssl/server-key.pem && chmod 600 /etc/mysql/ssl/server-key.pem
# RUN mkdir -p /usr/local/mysql/mysql-keyring && \
#     chmod 750 /usr/local/mysql/mysql-keyring && \
#     chown mysql:mysql /usr/local/mysql/mysql-keyring



# Copy file cấu hình my.cnf để bật ssl (tạo file my.cnf bên ngoài)
COPY my.cnf /etc/mysql/conf.d/my.cnf
