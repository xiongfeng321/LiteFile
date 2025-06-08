<?php
// LiteFile - A Lightweight Multi-User File Management System

// 引入配置文件，如果不存在则引导用户创建
if (!file_exists('config.php')) {
    die('<h1>错误：配置文件缺失</h1><p>请将 <code>config.sample.php</code> 复制为 <code>config.php</code>，并根据其中的说明进行配置。</p>');
}
require_once 'config.php';

// --- 调试与兼容性检查 ---
ini_set('display_errors', 1);
error_reporting(E_ALL);

if (version_compare(PHP_VERSION, '7.0.0', '<')) {
    write_log("致命错误：PHP版本过低。当前版本: " . PHP_VERSION);
    die('<h1>致命错误：PHP版本过低</h1><p>此程序需要 PHP 7.0.0 或更高版本才能运行。您服务器当前的PHP版本是：' . PHP_VERSION . '。</p>');
}
write_log("PHP版本检查通过。");

// --- 全局配置 ---
define('DB_FILE', 'data/database.sqlite');
define('UPLOAD_DIRECTORY', 'uploads');
define('RECORDS_PER_PAGE', 10);
write_log("全局配置已定义。");

// --- 数据库初始化与连接 ---
function get_db() {
    write_log("get_db() 函数被调用。");
    static $db = null;
    if ($db === null) {
        write_log("首次连接数据库。");
        if (!is_dir('data')) {
            write_log("'data' 目录不存在，正在尝试创建...");
            @mkdir('data', 0755, true);
        }
        if (!is_writable('data')) {
            write_log("致命错误: 'data' 目录不可写。");
            die("致命错误：'data' 目录不可写。请通过SSH登录服务器，执行 'sudo chown -R www-data:www-data /var/www/hugo' 命令来修复权限。");
        }
        try {
            write_log("准备执行 new PDO(...)。");
            $db = new PDO('sqlite:' . DB_FILE);
            write_log("PDO对象已创建。");
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            write_log("PDO属性已设置。");

            write_log("准备创建 users 表。");
            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
            write_log("users 表检查/创建完毕。");

            write_log("准备创建 records 表。");
            $db->exec("CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,
                file_url TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                remark TEXT,
                tags TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )");
            write_log("records 表检查/创建完毕。");

        } catch (PDOException $e) {
            write_log("致命错误：数据库连接失败: " . $e->getMessage());
            die("数据库连接失败: " . $e->getMessage() . "<br>请确保PHP的SQLite3扩展已安装 (sudo apt install php-sqlite3)。");
        }
    }
    write_log("get_db() 函数返回数据库对象。");
    return $db;
}

$db = get_db();

// --- 系统逻辑 ---
write_log("准备开始会话。");
@session_start();
write_log("会话已开始。");

$message = '';
$action_message = '';
$current_view = isset($_GET['view']) ? $_GET['view'] : 'login';
$logged_in_user = isset($_SESSION['user']) ? $_SESSION['user'] : null;
write_log("当前视图: {$current_view}。登录用户: " . ($logged_in_user ? $logged_in_user['username'] : '无'));

write_log("准备检查管理员是否存在。");
$stmt = $db->query("SELECT COUNT(*) FROM users WHERE role = 'admin'");
$admin_exists = $stmt->fetchColumn() > 0;
write_log("管理员存在: " . ($admin_exists ? '是' : '否'));

if (!$admin_exists && !in_array($current_view, ['setup'])) {
    write_log("无管理员，重定向到 setup 页面。");
    header('Location: ' . basename(__FILE__) . '?view=setup');
    exit;
}

// --- 辅助函数 ---
function format_bytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    if ($bytes > 0) {
        $bytes /= (1 << (10 * $pow));
    }
    return round($bytes, $precision) . ' ' . $units[$pow];
}
write_log("辅助函数已定义。");

// --- 请求路由 ---
write_log("进入请求路由... 视图: {$current_view}");
switch ($current_view) {
    case 'setup':
        write_log("处理 setup 视图。");
        if ($admin_exists) { header('Location: ?view=login'); exit; }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['admin_user']) && !empty($_POST['admin_pass'])) {
            $username = trim($_POST['admin_user']);
            $password_hash = password_hash($_POST['admin_pass'], PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, 'admin', 'approved')");
            $stmt->execute([$username, $password_hash]);
            $message = "管理员账号创建成功！请登录。";
            display_login_page($message);
            exit;
        }
        display_setup_page();
        break;

    case 'login':
        write_log("处理 login 视图。");
        if ($logged_in_user) { header('Location: ?view=dashboard'); exit; }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['username']) && !empty($_POST['password'])) {
            $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$_POST['username']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($_POST['password'], $user['password_hash'])) {
                if ($user['status'] === 'approved') {
                    $_SESSION['user'] = $user;
                    session_regenerate_id(true);
                    header('Location: ?view=dashboard');
                    exit;
                } else {
                    $message = "您的账号正在等待管理员审核或已被禁用。";
                }
            } else {
                $message = "用户名或密码错误。";
            }
        }
        display_login_page($message);
        break;

    case 'register':
        write_log("处理 register 视图。");
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['username']) && !empty($_POST['password'])) {
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $message = "用户名已被占用，请更换一个。";
            } else {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
                $stmt->execute([$username, $password_hash]);
                $message = "注册成功！请等待管理员审核后方可登录。";
            }
        }
        display_register_page($message);
        break;

    case 'dashboard':
        write_log("处理 dashboard 视图。");
        if (!$logged_in_user) { header('Location: ?view=login'); exit; }
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            write_log("Dashboard 收到 POST 请求。");
            $action = $_POST['action'] ?? '';
            write_log("Action: {$action}");
            
            if ($action === 'upload_file' && isset($_FILES['fileToUpload']) && $_FILES['fileToUpload']['error'] === UPLOAD_ERR_OK) {
                if (!is_writable(UPLOAD_DIRECTORY)) {
                     $message = '<p style="color: #ff4757;">错误：上传目录不可写！请检查服务器权限。</p>';
                } else {
                    $original_filename = basename($_FILES["fileToUpload"]["name"]);
                    $file_size = $_FILES['fileToUpload']['size'];
                    $safe_filename = time() . '-' . bin2hex(random_bytes(8)) . '.' . pathinfo($original_filename, PATHINFO_EXTENSION);
                    $target_file = UPLOAD_DIRECTORY . '/' . $safe_filename;

                    if (move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $target_file)) {
                        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
                        $host = $_SERVER['HTTP_HOST'];
                        $file_url = $protocol . $host . '/' . $target_file;
                        $remark = htmlspecialchars($_POST['remark'] ?? '');
                        $tags_str = htmlspecialchars($_POST['tags'] ?? '');
                        $stmt = $db->prepare("INSERT INTO records (user_id, original_filename, file_url, file_size, remark, tags, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))");
                        $stmt->execute([$logged_in_user['id'], $original_filename, $file_url, $file_size, $remark, $tags_str]);
                        $message = '<p style="color: #2ed573;">文件上传成功!</p>';
                    } else {
                        $message = '<p style="color: #ff4757;">抱歉，上传文件时发生错误。</p>';
                    }
                }
            }
            
            if ($action === 'save_code' && !empty($_POST['html_content'])) {
                $content = $_POST['html_content'];
                $file_size = strlen($content);
                $remark = htmlspecialchars($_POST['remark'] ?? '');
                $tags_str = htmlspecialchars($_POST['tags'] ?? '');
                $original_filename = !empty(trim($_POST['filename'])) ? trim($_POST['filename']) : 'pasted-snippet.html';
                if (pathinfo($original_filename, PATHINFO_EXTENSION) === '') {
                    $original_filename .= '.html';
                }
                $safe_filename = time() . '-' . bin2hex(random_bytes(8)) . '.html';
                $target_file = UPLOAD_DIRECTORY . '/' . $safe_filename;
                
                if (file_put_contents($target_file, $content) !== false) {
                    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
                    $host = $_SERVER['HTTP_HOST'];
                    $file_url = $protocol . $host . '/' . $target_file;
                    $stmt = $db->prepare("INSERT INTO records (user_id, original_filename, file_url, file_size, remark, tags, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))");
                    $stmt->execute([$logged_in_user['id'], $original_filename, $file_url, $file_size, $remark, $tags_str]);
                    $message = '<p style="color: #2ed573;">代码片段已成功保存为文件!</p>';
                } else {
                     $message = '<p style="color: #ff4757;">错误：无法写入文件，请检查目录权限。</p>';
                }
            }

            if ($action === 'delete' && isset($_POST['id'])) {
                $record_id = $_POST['id'];
                $sql = "SELECT file_url FROM records WHERE id = :id";
                if ($logged_in_user['role'] !== 'admin') $sql .= " AND user_id = :user_id";
                $stmt = $db->prepare($sql);
                $stmt->bindValue(':id', $record_id);
                if ($logged_in_user['role'] !== 'admin') $stmt->bindValue(':user_id', $logged_in_user['id']);
                $stmt->execute();
                $record = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($record) {
                    $filepath = parse_url($record['file_url'], PHP_URL_PATH);
                    if (file_exists(ltrim($filepath, '/'))) { @unlink(ltrim($filepath, '/')); }
                    $del_stmt = $db->prepare("DELETE FROM records WHERE id = :id");
                    $del_stmt->execute([':id' => $record_id]);
                    $action_message = '<p style="color: #2ed573;">记录已成功删除。</p>';
                }
            }
            if ($action === 'edit' && isset($_POST['id'])) {
                $sql = "UPDATE records SET remark = :remark, tags = :tags WHERE id = :id";
                if ($logged_in_user['role'] !== 'admin') $sql .= " AND user_id = :user_id";
                $stmt = $db->prepare($sql);
                $params = [':remark' => $_POST['remark'], ':tags' => $_POST['tags'], ':id' => $_POST['id']];
                if ($logged_in_user['role'] !== 'admin') $params[':user_id'] = $logged_in_user['id'];
                $stmt->execute($params);
                $action_message = '<p style="color: #1e90ff;">记录已成功更新。</p>';
            }
        }
        display_dashboard_page($logged_in_user, $db, $message, $action_message);
        break;
    
    case 'user_management':
        write_log("处理 user_management 视图。");
        if (!$logged_in_user || $logged_in_user['role'] !== 'admin') { header('Location: ?view=dashboard'); exit; }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id']) && isset($_POST['status'])) {
            $stmt = $db->prepare("UPDATE users SET status = ? WHERE id = ? AND role != 'admin'");
            $stmt->execute([$_POST['status'], $_POST['user_id']]);
            $action_message = "用户状态已更新。";
        }
        display_user_management_page($logged_in_user, $db, $action_message ?? '');
        break;

    case 'logout':
        write_log("处理 logout 视图。");
        session_destroy();
        header('Location: ?view=login');
        exit;

    default:
        write_log("处理 default 视图，重定向到 login。");
        header('Location: ?view=login');
        exit;
}
write_log("路由处理完毕。");


// --- 完整的HTML显示函数 ---

function display_dashboard_page($user, $db, $message, $action_message) {
    write_log("渲染 dashboard 页面。");
    // 准备数据
    $where_clauses = [];
    $params = [];

    if ($user['role'] !== 'admin') {
        $where_clauses[] = 'r.user_id = :user_id';
        $params[':user_id'] = $user['id'];
    }
    
    $search_term = isset($_GET['search']) ? trim($_GET['search']) : '';
    $tag_filter = isset($_GET['tag']) ? trim($_GET['tag']) : '';

    if (!empty($search_term)) {
        $where_clauses[] = '(r.original_filename LIKE :search OR r.remark LIKE :search OR r.tags LIKE :search)';
        $params[':search'] = '%' . $search_term . '%';
    }

    if (!empty($tag_filter)) {
        $where_clauses[] = '("," || r.tags || "," LIKE :tag)';
        $params[':tag'] = '%,' . $tag_filter . ',%';
    }

    $sql_base = "SELECT r.*, u.username FROM records r JOIN users u ON r.user_id = u.id";
    $sql_count_base = "SELECT COUNT(*) FROM records r";

    $sql_where = empty($where_clauses) ? '' : ' WHERE ' . implode(' AND ', $where_clauses);
    $sql = $sql_base . $sql_where . " ORDER BY r.timestamp DESC";
    $sql_count = $sql_count_base . $sql_where;

    write_log("准备执行COUNT查询: " . $sql_count);
    $stmt = $db->prepare($sql_count);
    $stmt->execute($params);
    $total_records = $stmt->fetchColumn();
    write_log("总记录数: {$total_records}");

    $total_pages = $total_records > 0 ? ceil($total_records / RECORDS_PER_PAGE) : 1;
    $current_page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
    $current_page = max(1, min($total_pages, $current_page));
    $start_index = ($current_page - 1) * RECORDS_PER_PAGE;

    $sql .= " LIMIT :limit OFFSET :offset";
    $stmt = $db->prepare($sql);
    foreach ($params as $key => &$val) { $stmt->bindParam($key, $val); }
    $stmt->bindValue(':limit', RECORDS_PER_PAGE, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $start_index, PDO::PARAM_INT);
    write_log("准备执行SELECT查询: " . $sql);
    $stmt->execute();
    $records_to_display = $stmt->fetchAll(PDO::FETCH_ASSOC);
    write_log("获取到 " . count($records_to_display) . " 条记录用于显示。");

    // 获取所有标签
    $tags_query = "SELECT tags FROM records";
    if ($user['role'] !== 'admin') {
        $tags_query .= " WHERE user_id = " . $user['id'];
    }
    $all_tags_raw = $db->query($tags_query)->fetchAll(PDO::FETCH_COLUMN);
    $all_tags = [];
    foreach ($all_tags_raw as $tags_str) {
        $all_tags = array_merge($all_tags, array_filter(array_map('trim', explode(',', $tags_str))));
    }
    $unique_tags = array_unique($all_tags);
    sort($unique_tags);
    write_log("获取到 " . count($unique_tags) . " 个唯一标签。");

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>文件管理面板</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { --dark-bg: #0a192f; --light-bg: #112240; --slate: #8892b0; --light-slate: #a8b2d1; --lightest-slate: #ccd6f6; --accent: #64ffda; --accent-dark: #139678; }
        body { font-family: 'Roboto Mono', monospace; line-height: 1.6; color: var(--slate); max-width: 1400px; margin: 20px auto; padding: 0 15px; background-color: var(--dark-bg); }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 28px; color: var(--lightest-slate); }
        .header-nav span { margin-right: 20px; color: var(--lightest-slate); }
        .header-nav a { text-decoration: none; background: transparent; color: var(--accent); padding: 8px 15px; border-radius: 4px; font-size:14px; margin-left: 10px; border: 1px solid var(--accent); transition: all 0.2s ease; }
        .header-nav a:hover { background: rgba(100, 255, 218, 0.1); }
        .header-nav .logout-btn { border-color: #ff7979; color: #ff7979; }
        .header-nav .logout-btn:hover { background: rgba(255, 121, 121, 0.1); }
        .container { background-color: var(--light-bg); padding: 30px; margin-bottom:20px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; padding-bottom:15px; color: var(--lightest-slate); font-size: 22px; }
        form p { margin: 20px 0 8px; font-size: 14px; color: var(--light-slate); }
        input[type="file"], input[type="text"], select, textarea { width: 100%; padding: 12px; box-sizing: border-box; background-color: var(--dark-bg); border: 1px solid #233554; border-radius: 4px; color: var(--lightest-slate); font-family: 'Roboto Mono', monospace;}
        textarea { height: 200px; resize: vertical; }
        input[type="submit"] { display: block; width: 100%; padding: 12px; margin-top: 25px; background-color: var(--accent); color: var(--dark-bg); border: none; border-radius: 4px; font-size: 16px; font-weight: bold; cursor: pointer; transition: background-color 0.2s; }
        input[type="submit"]:hover { background-color: var(--accent-dark); }
        #message, #action-message { margin: 20px 0; padding: 15px; background-color: rgba(30, 48, 80, 0.5); border-left: 3px solid var(--accent); border-radius: 4px; text-align: center;}
        .tabs { display: flex; border-bottom: 1px solid #233554; margin-bottom: 20px; }
        .tab-button { background: none; border: none; color: var(--slate); padding: 10px 20px; cursor: pointer; font-size: 16px; font-family: 'Roboto Mono', monospace; }
        .tab-button.active { color: var(--accent); border-bottom: 2px solid var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .filters { margin-bottom: 20px; display:flex; flex-wrap:wrap; align-items:center; gap:15px; }
        #searchInput { flex-grow: 1; min-width: 250px; }
        .tag-filters { display: flex; flex-wrap: wrap; gap: 8px; }
        .tag-filters a { text-decoration: none; }
        .tag-filters button { background-color: transparent; border: 1px solid var(--slate); color: var(--slate); padding: 5px 12px; border-radius: 15px; cursor: pointer; font-size: 13px; transition: all 0.2s; }
        .tag-filters button.active, .tag-filters button:hover { background-color: var(--accent); border-color: var(--accent); color: var(--dark-bg); font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 15px; border-bottom: 1px solid #233554; text-align: left; word-break: break-all; }
        th { color: var(--lightest-slate); font-size: 14px; }
        tr:hover { background-color: #1d2d44; }
        .preview-col { width: 80px; } .size-col { width: 100px; } .time-col { width: 160px; } .action-col { width: 120px; } .user-col { width: 100px; }
        .preview-col img { max-width: 60px; max-height: 60px; border-radius: 4px; object-fit: cover; }
        td a { color: var(--accent); text-decoration: none; }
        td a:hover { text-decoration: underline; }
        .tags span { background-color: #233554; color: var(--light-slate); padding: 4px 10px; margin-right: 5px; border-radius: 15px; font-size: 12px; white-space: nowrap; }
        .action-btn { background: transparent; color: #ffc107; border: 1px solid #ffc107; padding: 5px 10px; border-radius:4px; cursor:pointer; margin-right:5px; transition: all 0.2s; }
        .action-btn:hover { background: rgba(255, 193, 7, 0.1); }
        .delete-btn { color: #ff7979; border-color: #ff7979; }
        .delete-btn:hover { background: rgba(255, 121, 121, 0.1); }
        .save-btn { color: #2ed573; border-color: #2ed573; }
        .save-btn:hover { background: rgba(46, 213, 115, 0.1); }
        .pagination { text-align: center; margin-top: 30px; }
        .pagination a { color: var(--slate); padding: 8px 15px; text-decoration: none; border: 1px solid #233554; margin: 0 2px; border-radius: 4px; transition: all 0.2s; }
        .pagination a.active { background-color: var(--accent); color: var(--dark-bg); border-color: var(--accent); }
    </style>
</head>
<body>
    <div class="header">
        <h1>文件管理系统</h1>
        <div class="header-nav">
            <span>欢迎, <?php echo htmlspecialchars($user['username']); ?>!</span>
            <?php if ($user['role'] === 'admin'): ?>
                <a href="?view=user_management">用户管理</a>
            <?php endif; ?>
            <a href="?view=logout" class="logout-btn">退出登录</a>
        </div>
    </div>
    <div class="container">
        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'uploadFile')">文件上传</button>
            <button class="tab-button" onclick="openTab(event, 'pasteCode')">粘贴代码</button>
        </div>
        <div id="uploadFile" class="tab-content active">
            <h2>上传新文件</h2>
            <form action="?view=dashboard" method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload_file">
                <p>选择文件</p>
                <input type="file" name="fileToUpload" required>
                <p>备注（选填）</p>
                <input type="text" name="remark" placeholder="例如：这是五月份的工作报告">
                <p>标签（选填，用英文逗号 , 分隔）</p>
                <input type="text" name="tags" placeholder="例如: 工作,报告,重要">
                <input type="submit" value="上传并记录">
            </form>
        </div>
        <div id="pasteCode" class="tab-content">
            <h2>粘贴代码为文件</h2>
            <form action="?view=dashboard" method="post">
                <input type="hidden" name="action" value="save_code">
                <p>文件名 (例如: my-page.html)</p>
                <input type="text" name="filename" placeholder="pasted-snippet.html">
                <p>HTML / CSS / JS 代码</p>
                <textarea name="html_content" required></textarea>
                <p>备注（选填）</p>
                <input type="text" name="remark" placeholder="例如：一个登陆页面的模板">
                <p>标签（选填，用英文逗号 , 分隔）</p>
                <input type="text" name="tags" placeholder="例如: 模板,HTML,登录页">
                <input type="submit" value="保存代码为文件">
            </form>
        </div>
        <?php if ($message) echo "<div id='message'>$message</div>"; ?>
    </div>
    <div class="container">
        <h2><?php echo $user['role'] === 'admin' ? '所有用户的文件' : '我的文件'; ?> (共 <?php echo $total_records; ?> 条)</h2>
        <?php if ($action_message) echo "<div id='action-message'>$action_message</div>"; ?>
        <div class="filters">
            <input type="search" id="searchInput" placeholder="搜索文件名、备注、标签..." onchange="handleSearch(this.value)" value="<?php echo htmlspecialchars($search_term); ?>">
            <div class="tag-filters">
                <a href="?view=dashboard"><button class="<?php echo (empty($tag_filter) && empty($search_term)) ? 'active' : ''; ?>">全部</button></a>
                <?php foreach($unique_tags as $tag): ?>
                    <a href="?view=dashboard&tag=<?php echo urlencode($tag); ?>"><button class="<?php echo ($tag_filter == $tag) ? 'active' : ''; ?>"><?php echo htmlspecialchars($tag); ?></button></a>
                <?php endforeach; ?>
            </div>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead><tr><th class="preview-col">预览</th><th>文件名</th><th>备注</th><th>标签</th><?php if ($user['role'] === 'admin') echo '<th class="user-col">上传者</th>'; ?><th class="size-col">大小</th><th class="time-col">上传时间</th><th class="action-col">操作</th></tr></thead>
                <tbody>
                    <?php if (empty($records_to_display)): ?>
                        <tr><td colspan="<?php echo $user['role'] === 'admin' ? 8 : 7; ?>" style="text-align:center; padding: 30px;">暂无记录或未找到匹配项</td></tr>
                    <?php endif; ?>
                    <?php foreach($records_to_display as $record): 
                        $is_image = in_array(strtolower(pathinfo($record['original_filename'], PATHINFO_EXTENSION)), array('jpg', 'jpeg', 'png', 'gif', 'webp'));
                    ?>
                    <tr data-id="<?php echo $record['id']; ?>">
                        <td class="preview-col"><?php if($is_image): ?><a href="<?php echo $record['file_url']; ?>" target="_blank"><img src="<?php echo $record['file_url']; ?>" alt="预览"></a><?php else: ?><span>N/A</span><?php endif; ?></td>
                        <td><a href="<?php echo $record['file_url']; ?>" target="_blank"><?php echo htmlspecialchars($record['original_filename']); ?></a></td>
                        <td class="editable-remark"><?php echo htmlspecialchars($record['remark']); ?></td>
                        <td class="editable-tags tags">
                            <?php 
                            $tags = array_filter(array_map('trim', explode(',', $record['tags'])));
                            if(!empty($tags)) foreach($tags as $tag) echo "<span>".htmlspecialchars($tag)."</span>"; 
                            ?>
                        </td>
                        <?php if ($user['role'] === 'admin') echo '<td>' . htmlspecialchars($record['username']) . '</td>'; ?>
                        <td class="size-col"><?php echo format_bytes($record['file_size']); ?></td>
                        <td class="time-col"><?php echo $record['timestamp']; ?></td>
                        <td class="action-col">
                            <button class="action-btn" onclick="toggleEdit(this, '<?php echo $record['id']; ?>')">编辑</button>
                            <form action="?view=dashboard" method="post" style="display:inline;" onsubmit="return confirm('确定要永久删除这个文件和记录吗？');"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?php echo $record['id']; ?>"><button type="submit" class="action-btn delete-btn">删除</button></form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="pagination">
        <?php if ($total_pages > 1):
            $base_url = '?view=dashboard' . ($search_term ? '&search='.urlencode($search_term) : '') . ($tag_filter ? '&tag='.urlencode($tag_filter) : '');
        ?>
            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                <a href="<?php echo $base_url . '&page=' . $i; ?>" class="<?php echo ($i == $current_page) ? 'active' : ''; ?>"><?php echo $i; ?></a>
            <?php endfor; ?>
        <?php endif; ?>
        </div>
    </div>
    <script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tab-content");
        for (i = 0; i < tabcontent.length; i++) { tabcontent[i].style.display = "none"; }
        tablinks = document.getElementsByClassName("tab-button");
        for (i = 0; i < tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(" active", ""); }
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    function handleSearch(value) {
        window.location.href = '?view=dashboard&search=' + encodeURIComponent(value);
    }
    function toggleEdit(btn, id) {
        var row = btn.closest('tr');
        var isEditing = btn.textContent === '保存';
        var remarkCell = row.querySelector('.editable-remark');
        var tagsCell = row.querySelector('.editable-tags');
        if (isEditing) {
            var remarkInput = remarkCell.querySelector('input');
            var tagsInput = tagsCell.querySelector('input');
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '?view=dashboard';
            form.style.display = 'none';
            form.innerHTML = '<input name="action" value="edit"><input name="id" value="' + id + '"><input name="remark" value="' + escapeHtml(remarkInput.value) + '"><input name="tags" value="' + escapeHtml(tagsInput.value) + '">';
            document.body.appendChild(form);
            form.submit();
        } else {
            btn.textContent = '保存';
            btn.classList.add('save-btn');
            var currentRemark = remarkCell.textContent;
            remarkCell.innerHTML = '<input type="text" value="' + currentRemark + '" style="width:95%">';
            var currentTags = Array.from(tagsCell.querySelectorAll('span')).map(s => s.textContent).join(', ');
            tagsCell.innerHTML = '<input type="text" value="' + currentTags + '" style="width:95%">';
        }
    }
    function escapeHtml(text) {
        if(typeof text !== 'string') return '';
        var map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
    </script>
</body>
</html>
<?php
}

function display_user_management_page($user, $db, $action_message) {
    write_log("渲染 user_management 页面。");
    $stmt = $db->query("SELECT * FROM users ORDER BY created_at DESC");
    $all_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>用户管理</title><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet"><style>:root { --dark-bg: #0a192f; --light-bg: #112240; --slate: #8892b0; --light-slate: #a8b2d1; --lightest-slate: #ccd6f6; --accent: #64ffda; } body { font-family: 'Roboto Mono', monospace; color: var(--slate); max-width: 1400px; margin: 20px auto; padding: 0 15px; background-color: var(--dark-bg); } .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; margin-bottom: 20px; } .header h1 { margin: 0; font-size: 28px; color: var(--lightest-slate); } .header-nav a { text-decoration: none; background: transparent; color: var(--accent); padding: 8px 15px; border-radius: 4px; font-size:14px; margin-left: 10px; border: 1px solid var(--accent); transition: all 0.2s ease; } .header-nav a:hover { background: rgba(100, 255, 218, 0.1); } .header-nav .logout-btn { border-color: #ff7979; color: #ff7979; } .header-nav .logout-btn:hover { background: rgba(255, 121, 121, 0.1); } .container { background-color: var(--light-bg); padding: 30px; margin-bottom:20px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); } table { width: 100%; border-collapse: collapse; } th, td { padding: 15px; border-bottom: 1px solid #233554; text-align: left; } th { color: var(--lightest-slate); } select { background-color: var(--dark-bg); color: var(--slate); border: 1px solid #233554; padding: 5px; border-radius: 4px; }</style></head>
<body>
    <div class="header">
        <h1>用户管理</h1>
        <div class="header-nav"><a href="?view=dashboard">返回主面板</a><a href="?view=logout" class="logout-btn">退出登录</a></div>
    </div>
    <div class="container">
        <?php if($action_message) echo "<p style='color:#2ed573; text-align:center;'>$action_message</p>"; ?>
        <table>
            <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>注册时间</th><th>操作</th></tr></thead>
            <tbody>
                <?php foreach ($all_users as $u): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($u['username']); ?></td>
                        <td><?php echo htmlspecialchars($u['role']); ?></td>
                        <td><?php echo htmlspecialchars($u['status']); ?></td>
                        <td><?php echo $u['created_at']; ?></td>
                        <td>
                            <?php if ($u['id'] != $user['id']): ?>
                            <form action="?view=user_management" method="POST" style="display:inline;">
                                <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                <select name="status" onchange="this.form.submit()">
                                    <option value="approved" <?php if($u['status']=='approved') echo 'selected'; ?>>通过</option>
                                    <option value="pending" <?php if($u['status']=='pending') echo 'selected'; ?>>待审</option>
                                    <option value="revoked" <?php if($u['status']=='revoked') echo 'selected'; ?>>禁用</option>
                                </select>
                            </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body></html>
<?php
}

function display_login_page($message) {
    write_log("渲染 login 页面。");
?>
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>登录</title><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet"><style>:root{--dark-bg:#0a192f;--light-bg:#112240;--accent:#64ffda;}body,html{height:100%;margin:0;display:grid;place-items:center;background-color:var(--dark-bg);font-family:'Roboto Mono',monospace;} .login-box{padding:40px;background:var(--light-bg);border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center;width:340px;border:1px solid #233554;} h2{color:#ccd6f6;margin-bottom:25px;} input{width:100%;padding:12px;margin-bottom:15px;box-sizing:border-box;background:#0a192f;border:1px solid #233554;border-radius:4px;color:#ccd6f6;} button{width:100%;padding:12px;background:var(--accent);color:var(--dark-bg);border:none;font-weight:bold;border-radius:4px;cursor:pointer;} p{font-size:14px;color:#8892b0;} a{color:var(--accent);text-decoration:none;}</style></head>
<body>
    <div class="login-box">
        <h2>系统登录</h2>
        <?php if($message) echo "<p style='color:#ff7979;'>$message</p>"; ?>
        <form action="?view=login" method="POST">
            <input type="text" name="username" placeholder="用户名" required><br>
            <input type="password" name="password" placeholder="密码" required><br>
            <button type="submit">登录</button>
        </form>
        <p>还没有账号？ <a href="?view=register">立即注册</a></p>
    </div>
</body></html>
<?php
}

function display_register_page($message) {
    write_log("渲染 register 页面。");
?>
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>注册</title><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet"><style>:root{--dark-bg:#0a192f;--light-bg:#112240;--accent:#64ffda;}body,html{height:100%;margin:0;display:grid;place-items:center;background-color:var(--dark-bg);font-family:'Roboto Mono',monospace;} .login-box{padding:40px;background:var(--light-bg);border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center;width:340px;border:1px solid #233554;} h2{color:#ccd6f6;margin-bottom:25px;} input{width:100%;padding:12px;margin-bottom:15px;box-sizing:border-box;background:#0a192f;border:1px solid #233554;border-radius:4px;color:#ccd6f6;} button{width:100%;padding:12px;background:var(--accent);color:var(--dark-bg);border:none;font-weight:bold;border-radius:4px;cursor:pointer;} p{font-size:14px;color:#8892b0;} a{color:var(--accent);text-decoration:none;}</style></head>
<body>
    <div class="login-box">
        <h2>注册新账号</h2>
        <?php if($message) echo "<p style='color:#64ffda;'>$message</p>"; ?>
        <form action="?view=register" method="POST">
            <input type="text" name="username" placeholder="设置用户名" required><br>
            <input type="password" name="password" placeholder="设置密码" required><br>
            <button type="submit">注册</button>
        </form>
        <p>已有账号？ <a href="?view=login">返回登录</a></p>
    </div>
</body></html>
<?php
}

function display_setup_page() {
    write_log("渲染 setup 页面。");
?>
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>首次管理员设置</title><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet"><style>:root{--dark-bg:#0a192f;--light-bg:#112240;--accent:#64ffda;}body,html{height:100%;margin:0;display:grid;place-items:center;background-color:var(--dark-bg);font-family:'Roboto Mono',monospace;} .login-box{padding:40px;background:var(--light-bg);border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center;width:400px;border:1px solid #233554;} h2{color:#ccd6f6;margin-bottom:15px;} p{color:#8892b0;font-size:14px;} input{width:100%;padding:12px;margin-top:10px;margin-bottom:15px;box-sizing:border-box;background:#0a192f;border:1px solid #233554;border-radius:4px;color:#ccd6f6;} button{width:100%;padding:12px;background:var(--accent);color:var(--dark-bg);border:none;font-weight:bold;border-radius:4px;cursor:pointer;}</style></head>
<body>
    <div class="login-box">
        <h2>首次管理员设置</h2>
        <p>系统检测到尚未设置管理员账号，请创建您的第一个管理员账号。</p>
        <form action="?view=setup" method="POST">
            <input type="text" name="admin_user" placeholder="管理员用户名" required><br>
            <input type="password" name="admin_pass" placeholder="管理员密码" required><br>
            <button type="submit">创建管理员</button>
        </form>
    </div>
</body></html>
<?php
}
write_log("================= 脚本正常结束 =================");
?>
