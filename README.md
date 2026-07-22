# Dynamic Password Generator

基于UTC时间的动态密码生成器,使用Rust和Actix-web构建.

## 功能特性

- 基于UTC时间的动态密码生成
- 支持自定义时间偏移量
- 支持自定义时间输入
- 名称-盐值对管理 (添加,修改,删除)
- 配置文件持久化存储
- 多语言支持 (中文/英文)
- 可选的密码保护功能

## 技术栈

- Rust
- Actix-web
- SHA-256

## 快速开始

### 安装依赖

```bash
cargo build --release
```

### 运行

```bash
./target/release/calculate-dynamic-password.exe --port 8080
```

#### 启用密码保护

```bash
./target/release/calculate-dynamic-password.exe --port 8080 --password your-secret-password
```

启用密码保护后,访问网站前需要先输入密码登录.

#### 安全Cookie(HTTPS部署)

```bash
./target/release/calculate-dynamic-password.exe --port 8080 --password your-secret-password --secure-cookie
```

在HTTPS环境下部署时,使用`--secure-cookie`确保会话Cookie仅通过HTTPS传输.

#### 会话超时

启用密码保护后,会话超时时间为10分钟.如果用户持续交互,会话会自动刷新,永不过期.

### 访问

打开浏览器访问 `http://localhost:8080`

## API 接口

### 生成密码

```
POST /api/generate
Content-Type: application/json

{
  "salt": "your-salt",
  "offset": 0,
  "time": "2026010814"
}
```

### 获取盐值列表

```
GET /api/salts
```

### 添加/修改盐值对

```
POST /api/salts/add
Content-Type: application/json

{
  "name": "name",
  "salt": "salt"
}
```

### 删除盐值对

```
POST /api/salts/remove
Content-Type: application/json

{
  "name": "name"
}
```

### 刷新盐值列表

```
POST /api/salts/refresh
```

## 配置文件

配置文件存储在 `config/salts.json`,格式如下:

```json
[
  {
    "name": "example",
    "salt": "example-salt"
  }
]
```

## GitHub Actions

### 手动构建

项目提供了手动触发的构建工作流,支持选择分支或标签进行跨平台编译:

1. 打开 GitHub 仓库 → Actions → Build
2. 点击 "Run workflow"
3. 选择类型 (branch/tag) 和值 (如 `main` 或 `v1.0.0`)
4. 点击 "Run workflow"
5. 等待编译完成后,在 workflow 页面下载 artifacts

构建产物会保留7天.

### 自动发布

当推送标签(如 `v1.0.0`)时,会自动触发发布工作流,编译并创建 GitHub Release.

## Ubuntu 服务安装

使用 `install_ubuntu_service.sh` 脚本可以将应用安装为系统服务:

```bash
# 修改脚本中的配置参数
# SERVICE_NAME: 服务名称
# EXEC_PATH: 可执行文件路径
# EXEC_ARGS: 运行参数

sudo bash install_ubuntu_service.sh
```

## 许可证

MIT License