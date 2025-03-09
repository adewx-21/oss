from flask import Flask, request, jsonify, send_from_directory, url_for
from werkzeug.utils import secure_filename
from flask_cors import CORS
import os
from datetime import datetime
import mimetypes
import socket
import logging
import subprocess
import platform
from nacos import NacosClient
import json
import atexit
import time
import threading

app = Flask(__name__, 
    static_url_path='',
    static_folder='static'
)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_local_ip():
    try:
        # 获取所有网络接口的IP地址
        # Windows系统
        if platform.system() == "Windows":
            # 使用ipconfig命令获取IP地址
            output = subprocess.check_output("ipconfig", shell=True).decode()
            lines = output.split('\n')
            for line in lines:
                if "IPv4" in line and "192.168" in line:
                    return line.split(": ")[1].strip()
                elif "IPv4" in line and "10." in line:
                    return line.split(": ")[1].strip()
        # Linux/Mac系统
        else:
            # 使用hostname命令获取IP地址
            output = subprocess.check_output("hostname -I", shell=True).decode()
            ips = output.split()
            for ip in ips:
                if ip.startswith(('192.168', '10.')):
                    return ip
        
        # 如果上述方法失败，使用socket方法
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            if not ip.startswith(('127.', '172.')):  # 排除本地回环和Docker地址
                return ip
        finally:
            s.close()
            
        # 如果还是失败，尝试获取所有网络接口
        interfaces = socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET)
        for addr in interfaces:
            ip = addr[4][0]
            if ip.startswith(('192.168', '10.')) and not ip.startswith('172.'):
                return ip
                
        return '127.0.0.1'  # 如果都失败了，返回localhost
        
    except Exception as e:
        logger.error(f"Error getting IP: {e}")
        return '127.0.0.1'

# 服务器配置
SERVER_IP = get_local_ip()
# 如果使用了Nginx反向代理，使用实际的域名或IP
SERVER_PORT = int(os.getenv('PORT', 8080))  # Koyeb会通过PORT环境变量指定端口
BASE_URL = os.getenv('BASE_URL', 'https://your-app.koyeb.app')  # 部署后更新为实际URL

print(f"\n当前使用的IP地址: {SERVER_IP}")
print("如果这个IP地址不正确，请手动修改SERVER_IP变量为您的实际IP地址")

# CORS配置
CORS(app, supports_credentials=True)

# 文件上传配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 确保子文件夹存在
for subfolder in ['documents', 'images', 'videos']:
    subfolder_path = os.path.join(UPLOAD_FOLDER, subfolder)
    if not os.path.exists(subfolder_path):
        os.makedirs(subfolder_path, exist_ok=True)

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500MB
    SECRET_KEY='your_secret_key_here'
)

# 允许的文件类型
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp',  # 图片
    'txt', 'pdf', 'doc', 'docx',          # 文档
    'mp4', 'avi', 'mov', 'wmv', 'flv'     # 视频
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    try:
        # 确保static文件夹中存在index.html
        return app.send_static_file('index.html')
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return jsonify({
            'error': 'Static files not found. Please ensure static/index.html exists.',
            'details': str(e)
        }), 500

@app.route('/upload', methods=['POST', 'OPTIONS'])
def upload_file():
    if request.method == 'OPTIONS':
        return '', 204

    try:
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400

        if file and allowed_file(file.filename):
            # 生成文件名
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            
            # 确定文件类型和子文件夹
            ext = filename.rsplit('.', 1)[1].lower()
            if ext in ['mp4', 'avi', 'mov', 'wmv', 'flv']:
                sub_folder = 'videos'
            elif ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
                sub_folder = 'images'
            else:
                sub_folder = 'documents'

            # 创建子文件夹
            sub_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], sub_folder)
            os.makedirs(sub_folder_path, exist_ok=True)

            # 保存文件
            file_path = os.path.join(sub_folder_path, filename)
            file.save(file_path)
            
            # 生成访问URL
            file_url = f"{BASE_URL}/file/{sub_folder}/{filename}"
            
            logger.info(f"File uploaded successfully: {file_url}")
            return jsonify({
                'message': '文件上传成功',
                'url': file_url,
                'file_type': ext
            })

        return jsonify({'error': '不支持的文件类型'}), 400

    except Exception as e:
        logger.error(f"Upload error: {e}")
        if 'Request Entity Too Large' in str(e):
            return jsonify({'error': '文件大小超过限制(500MB)'}), 413
        return jsonify({'error': f'上传失败: {str(e)}'}), 500

# 文件访问路由
@app.route('/file/<path:filename>')
def serve_file(filename):
    try:
        # 添加详细日志
        logger.info(f"Attempting to serve file: {filename}")
        
        # 从路径中提取子文件夹和文件名
        parts = filename.split('/')
        if len(parts) > 1:
            sub_folder = parts[0]
            actual_filename = '/'.join(parts[1:])
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], sub_folder)
            full_path = os.path.join(file_path, actual_filename)
        else:
            file_path = app.config['UPLOAD_FOLDER']
            actual_filename = filename
            full_path = os.path.join(file_path, actual_filename)
            
        logger.debug(f"Full file path: {full_path}")
        logger.debug(f"File exists: {os.path.exists(full_path)}")
        
        if not os.path.exists(full_path):
            logger.error(f"File not found: {full_path}")
            return jsonify({'error': '文件不存在', 'path': full_path}), 404

        # 检查文件权限
        try:
            with open(full_path, 'rb') as f:
                pass
        except PermissionError:
            logger.error(f"Permission denied accessing file: {full_path}")
            return jsonify({'error': '文件访问权限被拒绝'}), 403

        response = send_from_directory(file_path, actual_filename)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Cache-Control'] = 'no-cache'
        
        logger.info(f"File served successfully: {filename}")
        return response

    except Exception as e:
        logger.error(f"File serving error: {str(e)}", exc_info=True)
        return jsonify({
            'error': '文件访问失败',
            'details': str(e),
            'filename': filename,
            'upload_folder': app.config['UPLOAD_FOLDER']
        }), 500

# Nacos配置
NACOS_SERVER_ADDR = os.getenv('NACOS_SERVER_ADDR', "113.44.56.231:8848")
NACOS_NAMESPACE = os.getenv('NACOS_NAMESPACE', "public")
SERVICE_NAME = os.getenv('SERVICE_NAME', "STYLE_AI@@file-save-service")

# 创建Nacos客户端
nacos_client = NacosClient(
    server_addresses=NACOS_SERVER_ADDR,
    namespace=NACOS_NAMESPACE,
    username="admin",  
    password="admin"   
)

def register_service():
    """注册服务到Nacos"""
    try:
        # 服务实例信息
        instance = {
            "ip": SERVER_IP,
            "port": SERVER_PORT,
            "metadata": {
                "preserved.register.source": "PYTHON_SDK",
                "service.type": "file-upload",
                "version": "1.0.0",
                "group": "STYLE_AI"  # 添加组信息到元数据
            },
            "healthy": True,
            "weight": 1.0,
            "enabled": True,
            "ephemeral": True  # 临时实例
        }
        
        # 注册服务实例
        success = nacos_client.register_instance(
            service_name=SERVICE_NAME,
            ip=SERVER_IP,
            port=SERVER_PORT,
            metadata=instance["metadata"],
            group_name="STYLE_AI"  # 添加组名参数
        )
        
        if success:
            logger.info(f"Successfully registered service to Nacos: {SERVICE_NAME}")
        else:
            logger.error("Failed to register service to Nacos")
            
    except Exception as e:
        logger.error(f"Error registering service to Nacos: {e}")

def deregister_service():
    """从Nacos注销服务"""
    try:
        success = nacos_client.deregister_instance(
            service_name=SERVICE_NAME,
            ip=SERVER_IP,
            port=SERVER_PORT,
            group_name="STYLE_AI"  # 添加组名参数
        )
        if success:
            logger.info(f"Successfully deregistered service from Nacos: {SERVICE_NAME}")
        else:
            logger.error("Failed to deregister service from Nacos")
    except Exception as e:
        logger.error(f"Error deregistering service from Nacos: {e}")

def send_heartbeat():
    """发送心跳到Nacos"""
    while True:
        try:
            success = nacos_client.send_heartbeat(
                service_name=SERVICE_NAME,
                ip=SERVER_IP,
                port=SERVER_PORT,
                metadata={
                    "preserved.register.source": "PYTHON_SDK",
                    "service.type": "file-upload",
                    "version": "1.0.0",
                    "group": "STYLE_AI"  # 添加组信息到元数据
                },
                group_name="STYLE_AI"  # 添加组名参数
            )
            
            if success:
                logger.debug("Successfully sent heartbeat to Nacos")
            else:
                logger.warning("Failed to send heartbeat to Nacos")
            
        except Exception as e:
            logger.error(f"Error sending heartbeat to Nacos: {e}")
            
        time.sleep(5)  # 每5秒发送一次心跳

# 修改健康检查路由，增加Nacos相关信息
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'server_ip': SERVER_IP,
        'upload_folder': UPLOAD_FOLDER,
        'service_name': SERVICE_NAME,
        'nacos_server': NACOS_SERVER_ADDR,
        'nacos_namespace': NACOS_NAMESPACE
    })

if __name__ == '__main__':
    # 在生产环境中,我们可能不需要注册Nacos服务
    if os.getenv('ENABLE_NACOS', 'false').lower() == 'true':
        register_service()
        heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
        heartbeat_thread.start()
        atexit.register(deregister_service)
    
    app.run(
        host='0.0.0.0',
        port=SERVER_PORT,
        debug=False,  # 生产环境关闭debug模式
        threaded=True
    ) 