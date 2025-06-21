# giải thích các file và thư mục

## apisix-key
- Nó không làm gì cả, bỏ nó đi=)))
- Nhưng mà ta sẽ tạo cái private key chung ấy. Tôi dã thử test key chung bỏ vào code, ở hàm `verify_apisix_jwt` để test rồi

## database_key_cert
- Chứa cái chứng chỉ CA dùng để xác thực 2 bên gọi
- Cái client-key sẽ dùng để tạo ra cert thôi
- client-cert sẽ được áp vào code để khi gọi đến DB thì nó sẽ kiểm tra

## thư mục jwt
- Dùng để xác thực người dùng và ký người dùng (JWT)

## ssl_cert
- Cái này dùng để chứng chỉ tự ký để mà chạy https thôi. Nhưng ae mình thống nhất "suỵt" chỗ này nên là ko cần quan tâm lắm=))))
