CREATE DATABASE IF NOT EXISTS tmdt;
-- INSTALL PLUGIN keyring_file SONAME 'keyring_file.so';
USE tmdt;

CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(96) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
); --ENGINE=InnoDB ENCRYPTION='Y';
CREATE TABLE products (
    id INT NOT NULL AUTO_INCREMENT,
    product_name VARCHAR(255) NOT NULL UNIQUE,
    price DECIMAL(12,2) NOT NULL,
    quantity_available INT DEFAULT 0,
    PRIMARY KEY (id)
); -- ENGINE=InnoDB ENCRYPTION='Y';

CREATE TABLE orders (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    price DECIMAL(12,2) NOT NULL,
    quantity INT DEFAULT 1,
    purchase_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (username) REFERENCES users(username)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (product_name) REFERENCES products(product_name)
        ON UPDATE CASCADE ON DELETE CASCADE
); -- ENGINE=InnoDB ENCRYPTION='Y';


CREATE TABLE blacklist (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    jti VARCHAR(100),
    PRIMARY KEY (id)
); -- ENGINE=InnoDB ENCRYPTION='Y';

CREATE TABLE otp_codes (
    username VARCHAR(255) PRIMARY KEY,
    otp_code VARCHAR(10),
    expires_at DATETIME
); -- ENGINE=InnoDB ENCRYPTION='Y';

--INSERT INTO users(username, hashed_password, role) VALUES ("dangnosuy", "ac1e1272d0454ef606e8d58ad59a0456dc0878fd41f697d6be7cd8b9e66ef55c5147b6aa3912fbe0487a2d1e1c7c873a", "admin");
