# LiteFile - 轻量级多用户文件管理系统

一个简单、安全、开箱即用的PHP单文件多用户文件管理系统。拥有现代化的科技感UI，支持文件上传、代码粘贴、在线编辑、多用户权限管理等功能。

![image](https://github.com/user-attachments/assets/ad8b71f5-79a7-4771-8b63-522450d0f543)

登录界面


![image](https://github.com/user-attachments/assets/3a0a4cef-1bb7-4b7d-a6ee-276c66e820b1)
操作界面

## ✨ 主要功能

- **多用户系统**：支持用户注册和管理员审核。
- **权限隔离**：管理员可查看所有文件，普通用户只能查看和管理自己的文件。
- **双上传模式**：支持直接上传文件，也支持粘贴HTML/CSS/JS代码直接生成文件。
- **文件管理**：支持在线对文件的备注和标签进行编辑。
- **一键删除**：可一键删除文件记录及其源文件。
- **图片预览**：自动为上传的图片生成缩略图。
- **搜索与筛选**：强大的实时搜索和标签云筛选功能。
- **美观UI**：基于深色模式的现代化科技感界面。
- **轻量部署**：基于SQLite，无需安装额外数据库，整个系统几乎是一个单文件。

## 🚀 环境要求

- PHP >= 7.0.0
- PHP PDO 扩展
- PHP SQLite3 扩展 (`php-sqlite3`)
- Web 服务器 (推荐 Nginx)

## 🛠️ 安装步骤

1. 下载本项目的所有文件。

2. 将 `config.sample.php` 文件复制一份，并重命名为 `config.php`。

3. **（关键）** 打开 `config.php`，将 `ADMIN_PASSWORD_HASH` 的值设置为空字符串 `''`。

4. 将所有文件上传到您的PHP网站服务器目录。

5. 确保服务器对您的项目根目录有写入权限，程序会自动创建 `data` 和 `uploads` 两个文件夹。如果创建失败，请手动创建这两个文件夹，并赋予PHP写入权限（例如 `sudo chown -R www-data:www-data /您的项目目录`）。

## 🌐 Web服务器配置 (Nginx 示例)

   您需要配置Web服务器，使其能正确处理PHP请求。以下是一份推荐的 Nginx 配置文件 `server` 块示例：

   ```
   server {
       listen 80;
       # 将 your_domain.com 替换为您的域名或服务器IP
       server_name your_domain.com; 
       
       # 将 /path/to/your/project 替换为您项目文件的实际路径
       root /path/to/your/project; 
       index index.php;
   
       location / {
           try_files $uri $uri/ /index.php?$query_string;
       }
   
       # 将所有 .php 请求传递给 PHP-FPM 服务
       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           
           # 请根据您服务器的实际情况，确认php-fpm.sock文件的路径
           # 例如：unix:/var/run/php/php7.4-fpm.sock
           fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
       }
   
       # 禁止通过浏览器直接访问敏感目录和文件，增加安全性
       location ~ /(data|config\.php) {
           deny all;
       }
       location ~ /\.ht {
           deny all;
       }
   }
   ```

   **配置完成后，请不要忘记重启 Nginx 服务 (`sudo systemctl restart nginx`)。**

   #### 🏁 首次使用

   1. 在浏览器中访问您配置好的域名或IP地址。
   2. 程序会自动引导您进入**“首次管理员设置”**页面。
   3. 设置您的第一个管理员账号和密码。
   4. 设置成功后，程序会引导您登录。之后，您可以进入“用户管理”后台，审核其他新注册的用户。

   #### 🤔 常见问题 (FAQ)

   - **问：访问页面显示空白/500错误/一闪就空白？** 答：这是典型的PHP致命错误。请检查：
     1. **环境要求**：确保您服务器的PHP版本>=7.0，且已安装 `php-pdo` 和 `php-sqlite3` 扩展。
     2. **目录权限**：运行 `sudo chown -R www-data:www-data /您的项目目录` 确保PHP有权限写入 `data` 和 `uploads` 文件夹。
     3. **PHP服务**：运行 `sudo systemctl status php*-fpm` 检查PHP-FPM服务是否正在运行。如果不是，请用 `restart` 命令重启它。
   - **问：提示 `could not find driver` 错误？** 答：说明缺少PHP的SQLite3驱动。请在您的服务器上运行 `sudo apt update && sudo apt install php-sqlite3 -y` (Debian/Ubuntu) 或 `sudo yum install php-sqlite` (CentOS/RHEL)，然后重启PHP-FPM服务。

   #### 🛡️ 安全建议

   - **使用HTTPS**：强烈建议为您的网站配置SSL证书，使用HTTPS协议。这可以加密您和用户在登录、上传时的数据，防止密码和文件内容在传输过程中被窃听。
   - **设置强密码**：请为管理员账号设置一个足够复杂的密码。
   - **定期备份**：定期备份 `data` 目录（尤其是 `database.sqlite` 文件）和 `uploads` 目录，以防服务器故障或意外删除。
   - **更新服务器软件**：保持您的服务器操作系统、Nginx、PHP等软件为最新版本，以获取最新的安全补丁。

   #### 🤝 如何贡献

   欢迎为本项目做出贡献！您可以通过以下方式参与：

   1. **报告Bug**：通过GitHub的 `Issues` 提交您发现的问题。
   2. **提出功能建议**：同样通过 `Issues` 描述您希望增加的新功能。
   3. **提交代码**：如果您修复了Bug或开发了新功能，欢迎通过 `Pull Request` 的方式提交您的代码。

   #### 💡 未来计划

   - [ ] 文件分享链接增加密码和有效期设置。
   - [ ] 支持文件批量上传和删除。
   - [ ] 增加仪表盘，对文件类型、大小进行统计。
   - [ ] 优化移动端界面体验。

   #### 📄 开源许可

   本项目基于 [MIT License](LICENSE) 开源。

