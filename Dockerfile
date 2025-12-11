# 使用 Node.js 18 作为基础镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制 package.json
COPY package.json ./

# 安装依赖
RUN npm install --production

# 复制源代码
COPY server.js ./

# 创建上传目录
RUN mkdir uploads

# 暴露端口 (Render 会自动设置 PORT 环境变量，默认 3000)
EXPOSE 3000

# 启动命令
CMD ["npm", "start"]
