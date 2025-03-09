# 使用Python 3.9作为基础镜像
FROM python:3.9-slim

# 安装tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建上传文件夹
RUN mkdir -p uploads/documents uploads/images uploads/videos

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=8080

# 暴露端口
EXPOSE 8080

# 使用tini作为入口点
ENTRYPOINT ["/tini", "--"]

# 启动命令
CMD ["python", "app.py"] 
