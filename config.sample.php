<?php
// LiteFile 配置文件

// --- 安全配置 ---
// !! 重要：这是您系统的登录密码哈希值。
// 首次使用时，请将您的密码通过程序首页的“首次管理员设置”生成的哈希值粘贴到这里。
// 例如: $password_hash = '$2y$10$abc...';
define('ADMIN_PASSWORD_HASH', '');


// --- 基础配置 ---

// 上传文件存放的目录名
define('UPLOAD_DIRECTORY', 'uploads');

// 数据库和记录文件存放的目录名
define('DATA_DIRECTORY', 'data');

// 数据库文件名
define('DB_FILE', DATA_DIRECTORY . '/database.sqlite');

// 每页显示的记录数
define('RECORDS_PER_PAGE', 10);

?>