CREATE DATABASE IF NOT EXISTS invex_employees CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON invex_employees.* TO 'admin'@'%';
FLUSH PRIVILEGES;
