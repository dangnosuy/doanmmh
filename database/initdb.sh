# #!/bin/bash
# mysql -u dangnosuy -p dangnosuy -e "INSTALL PLUGIN keyring_file SONAME 'keyring_file.so';"
# service mysql restart


# Quăng vô my.cnf
# early-plugin-load=keyring_file.so
# keyring_file_data=/usr/local/mysql/mysql-keyring/keyring
# innodb_file_per_table=ON
# binlog_encryption=ON
# innodb_redo_log_encrypt=ON