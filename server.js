// ===========================================
// 🛠️ 环境清理 (防止代理干扰)
// ===========================================
delete process.env.HTTP_PROXY
delete process.env.HTTPS_PROXY
delete process.env.http_proxy
delete process.env.https_proxy
process.env.NO_PROXY = '*'

const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const axios = require('axios')
const cors = require('cors')
const express = require('express')
const multer = require('multer')
const { Pool } = require('pg')

const app = express()
app.use(cors())
app.use(express.json())
const upload = multer({ dest: 'uploads/' })

// 确保 uploads 目录存在
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// PostgreSQL 连接池
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
})

// ================= 配置区域 =================
// 即梦 API Token
const JIMENG_TOKENS = (process.env.JIMENG_TOKEN || '304d66838b09f810b70e2c14a81978f9').split(',').map(t => t.trim()).filter(t => t)
const BLEND_MODEL_V40 = 'high_aes_general_v40' // 4.0 版本 (高速)
const BLEND_MODEL_V41 = 'high_aes_general_v41' // 4.1 版本 (高质量)
let currentTokenIndex = 0

// 微信小程序配置
const WECHAT_APPID = process.env.WECHAT_APPID || 'your_wechat_appid'
const WECHAT_SECRET = process.env.WECHAT_SECRET || 'your_wechat_secret'

// JWT 配置
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_change_this'
const ACCESS_TOKEN_EXPIRES = 7200 // 2小时
const REFRESH_TOKEN_EXPIRES = 2592000 // 30天

// 获取下一个 Token (轮询)
function getNextToken() {
  const token = JIMENG_TOKENS[currentTokenIndex]
  currentTokenIndex = (currentTokenIndex + 1) % JIMENG_TOKENS.length
  return token
}
// ===========================================

// --- 基础工具 ---
function generateUuid() {
  if (crypto.randomUUID)
    return crypto.randomUUID()
  return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16))
}
const jsonEncode = obj => JSON.stringify(obj)

// 生成随机头像
function getRandomAvatar() {
  const styles = ['adventurer', 'avataaars', 'bottts', 'fun-emoji', 'lorelei', 'micah', 'miniavs', 'pixel-art']
  const style = styles[Math.floor(Math.random() * styles.length)]
  const seed = Math.random().toString(36).substring(7)
  return `https://api.dicebear.com/7.x/${style}/svg?seed=${seed}`
}

// JWT 编码
function encodeJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' }
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const message = `${encodedHeader}.${encodedPayload}`
  
  const signature = crypto.createHmac('sha256', secret).update(message).digest('base64url')
  return `${message}.${signature}`
}

// JWT 解码
function decodeJWT(token, secret) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.')
    const message = `${encodedHeader}.${encodedPayload}`
    
    const expectedSignature = crypto.createHmac('sha256', secret).update(message).digest('base64url')
    if (signature !== expectedSignature) return null
    
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString())
    if (payload.exp && payload.exp < Date.now() / 1000) return null
    
    return payload
  } catch (e) {
    return null
  }
}

// 生成 Token 对
function generateTokens(userId) {
  const now = Math.floor(Date.now() / 1000)
  
  const accessToken = encodeJWT({
    userId,
    type: 'access',
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRES
  }, JWT_SECRET)
  
  const refreshToken = encodeJWT({
    userId,
    type: 'refresh',
    iat: now,
    exp: now + REFRESH_TOKEN_EXPIRES
  }, JWT_SECRET)
  
  return {
    accessToken,
    refreshToken,
    accessExpiresIn: ACCESS_TOKEN_EXPIRES,
    refreshExpiresIn: REFRESH_TOKEN_EXPIRES
  }
}

// 验证 Token
function verifyToken(req) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null
  }
  
  const token = authHeader.substring(7)
  const payload = decodeJWT(token, JWT_SECRET)
  
  if (!payload || payload.type !== 'access') {
    return null
  }
  
  return payload
}

// JSON 响应
function jsonResponse(res, data, status = 200) {
  return res.status(status).json(data)
}

function crc32(buffer) {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1))
    table[i] = c
  }
  let crc = 0 ^ (-1)
  for (let i = 0; i < buffer.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buffer[i]) & 0xFF]
  }
  return ((crc ^ (-1)) >>> 0).toString(16)
}

function generateCookie(token) {
  const WEB_ID = (Math.random() * 1e18 + 7e18).toString()
  const USER_ID = generateUuid().replace(/-/g, '')
  return [
    `sessionid=${token}`,
    `sessionid_ss=${token}`,
    `sid_tt=${token}`,
    `uid_tt=${USER_ID}`,
    `_tea_web_id=${WEB_ID}`,
  ].join('; ')
}

// 请求封装
async function request(method, urlPath, data = {}, params = {}, extraHeaders = {}, token) {
  const baseUrl = 'https://jimeng.jianying.com'
  const url = urlPath.startsWith('http') ? urlPath : `${baseUrl}${urlPath}`

  // 如果没有传入 token，尝试获取默认或下一个（仅作为兜底，正常业务逻辑应传入）
  const activeToken = token || getNextToken()

  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Appid': '513695',
    'Appvr': '8.4.0',
    'Pf': '7',
    'Origin': 'https://jimeng.jianying.com',
    'Referer': 'https://jimeng.jianying.com/ai-tool/generate/?type=image',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Cookie': generateCookie(activeToken),
    ...extraHeaders,
  }

  try {
    const response = await axios({
      method,
      url,
      data: method !== 'GET' ? data : undefined,
      params,
      proxy: false,
      httpsAgent: new (require('node:https').Agent)({ rejectUnauthorized: false }),
      headers,
    })
    return response.data
  }
  catch (e) {
    console.error(`请求失败 [${url}]:`, e.response?.data || e.message)
    throw new Error(e.response?.data || e.message)
  }
}

// AWS V4 签名
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest() }
function hmacHex(key, data) { return crypto.createHmac('sha256', key).update(data).digest('hex') }
function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex') }

function getAwsAuthHeaders(accessKey, secretKey, sessionToken, region, service, method, params, headers, body = {}) {
  const now = new Date()
  const amzDate = `${now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15)}Z`
  const dateStamp = amzDate.slice(0, 8)

  const lowerHeaders = {}
  Object.keys(headers).forEach(k => lowerHeaders[k.toLowerCase()] = headers[k].trim())
  lowerHeaders['x-amz-date'] = amzDate
  lowerHeaders['x-amz-security-token'] = sessionToken

  const sortedHeaderKeys = Object.keys(lowerHeaders).sort()
  const canonicalHeaders = sortedHeaderKeys.map(k => `${k}:${lowerHeaders[k]}\n`).join('')
  const signedHeaders = sortedHeaderKeys.join(';')

  const canonicalQuery = Object.keys(params).sort().map(k => `${k}=${encodeURIComponent(params[k])}`).join('&')
  const payloadHash = sha256(method === 'GET' ? '' : JSON.stringify(body))

  const canonicalRequest = [method, '/', canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n')
  const algorithm = 'AWS4-HMAC-SHA256'
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`
  const stringToSign = [algorithm, amzDate, credentialScope, sha256(canonicalRequest)].join('\n')

  const kDate = hmac(`AWS4${secretKey}`, dateStamp)
  const kRegion = hmac(kDate, region)
  const kService = hmac(kRegion, service)
  const kSigning = hmac(kService, 'aws4_request')
  const signature = hmacHex(kSigning, stringToSign)

  return {
    ...headers,
    'X-Amz-Date': amzDate,
    'X-Amz-Security-Token': sessionToken,
    'Authorization': `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  }
}

async function imagexRequest(method, url, params, headers, data) {
  const queryString = Object.keys(params).sort().map(k => `${k}=${encodeURIComponent(params[k])}`).join('&')
  return axios({
    method,
    url: queryString ? `${url}?${queryString}` : url,
    headers,
    data,
    proxy: false,
    httpsAgent: new (require('node:https').Agent)({ rejectUnauthorized: false }),
  }).then(r => r.data)
}

// 1. 上传图片
async function uploadImage(filePath, token) {
  console.log('📡 [1/4] 正在获取上传凭证...')
  const authRes = await request('POST', '/mweb/v1/get_upload_token', { scene: 2 }, {
    aid: 513695,
    da_version: '3.3.4',
    aigc_features: 'app_lip_sync',
  }, token)

  const auth = authRes.data
  if (!auth)
    throw new Error('Token 无效，无法获取上传凭证')

  console.log('📤 [2/4] 正在上传图片数据...')
  const fileBuffer = fs.readFileSync(filePath)
  const crc = crc32(fileBuffer)

  const uploadParams = {
    Action: 'ApplyImageUpload',
    FileSize: fileBuffer.length,
    ServiceId: 'tb4s082cfz',
    Version: '2018-08-01',
    s: Math.random().toString(36).slice(2),
  }

  const applyHeaders = getAwsAuthHeaders(auth.access_key_id, auth.secret_access_key, auth.session_token, 'cn-north-1', 'imagex', 'GET', uploadParams, { Host: 'imagex.bytedanceapi.com' })
  const applyRes = await imagexRequest('GET', 'https://imagex.bytedanceapi.com/', uploadParams, applyHeaders)

  if (!applyRes.Result?.UploadAddress)
    throw new Error('ApplyUpload 失败')

  const uploadAddr = applyRes.Result.UploadAddress
  const storeUri = uploadAddr.StoreInfos[0].StoreUri
  const uploadHost = uploadAddr.UploadHosts[0]
  const uploadUrl = `https://${uploadHost}/upload/v1/${storeUri}`

  await imagexRequest('POST', uploadUrl, {}, {
    'Authorization': uploadAddr.StoreInfos[0].Auth,
    'Content-Crc32': crc,
    'Content-Type': 'application/octet-stream',
  }, fileBuffer)

  console.log('✅ [3/4] 提交上传确认...')
  const commitParams = { Action: 'CommitImageUpload', FileSize: fileBuffer.length, ServiceId: 'tb4s082cfz', Version: '2018-08-01' }
  const commitBody = { SessionKey: uploadAddr.SessionKey }
  const commitHeaders = getAwsAuthHeaders(auth.access_key_id, auth.secret_access_key, auth.session_token, 'cn-north-1', 'imagex', 'POST', commitParams, { 'Host': 'imagex.bytedanceapi.com', 'Content-Type': 'application/json' }, commitBody)

  const commitRes = await imagexRequest('POST', 'https://imagex.bytedanceapi.com/', commitParams, commitHeaders, commitBody)
  const uri = commitRes.Result.Results[0].Uri

  console.log('🔍 [4/4] 提交图片审核...')
  await request('POST', '/mweb/v1/imagex/submit_audit_job', {
    uri_list: [uri],
  }, {
    aid: 513695,
    web_version: '7.5.0',
    da_version: '3.3.4',
    aigc_features: 'app_lip_sync',
  }, token)
  console.log('✅ 审核提交成功')

  return uri
}

// 2. 生成图片 (图生图)
async function generate(imageUri, promptText, token, modelId = BLEND_MODEL_V40) {
  console.log(`🎨 开始生成任务，参考图URI: ${imageUri}，提示词: ${promptText}，模型: ${modelId}`)

  const componentId = generateUuid()
  const submitId = generateUuid()

  const draftContent = {
    type: 'draft',
    id: generateUuid(),
    min_version: '3.0.2',
    min_features: [],
    is_from_tsn: true,
    version: '3.3.4',
    main_component_id: componentId,
    component_list: [{
      type: 'image_base_component',
      id: componentId,
      min_version: '3.0.2',
      aigc_mode: 'workbench',
      metadata: {
        type: '',
        id: generateUuid(),
        created_platform: 3,
        created_platform_version: '',
        created_time_in_ms: Date.now().toString(),
        created_did: '',
      },
      generate_type: 'blend',
      abilities: {
        type: '',
        id: generateUuid(),
        blend: {
          type: '',
          id: generateUuid(),
          min_features: [],
          core_param: {
            type: '',
            id: generateUuid(),
            model: modelId,
            prompt: promptText, // 使用传入的提示词
            sample_strength: 0.5,
            image_ratio: 1,
            large_image_info: {
              type: '',
              id: generateUuid(),
              height: 2304,
              width: 1820,
              resolution_type: '2k',
            },
            intelligent_ratio: false,
          },
          ability_list: [{
            type: '',
            id: generateUuid(),
            name: 'byte_edit',
            image_uri_list: [imageUri],
            image_list: [{
              type: 'image',
              id: generateUuid(),
              source_from: 'upload',
              platform_type: 1,
              name: '',
              image_uri: imageUri,
              width: 0,
              height: 0,
              format: '',
              uri: imageUri,
            }],
            strength: 0.5,
          }],
          prompt_placeholder_info_list: [{
            type: '',
            id: generateUuid(),
            ability_index: 0,
          }],
          postedit_param: {
            type: '',
            id: generateUuid(),
            generate_type: 0,
          },
        },
        gen_option: {
          type: '',
          id: generateUuid(),
          generate_all: false,
        },
      },
    }],
  }

  const data = {
    extend: { root_model: modelId },
    submit_id: submitId,
    metrics_extra: jsonEncode({
      promptSource: 'custom',
      generateCount: 4,
      enterFrom: 'click',
      generateId: submitId,
      isRegenerate: false,
    }),
    draft_content: jsonEncode(draftContent),
    http_common_info: { aid: 513695 },
  }

  const WEB_ID = (Math.random() * 999999999999999999 + 7000000000000000000).toString()
  const params = {
    aid: 513695,
    device_platform: 'web',
    region: 'cn',
    webId: WEB_ID,
    da_version: '3.3.4',
    web_component_open_flag: '1',
    web_version: '7.5.0',
    aigc_features: 'app_lip_sync',
  }

  const res = await request('POST', '/mweb/v1/aigc_draft/generate', data, params, {}, token)

  if (!res.data?.aigc_data?.history_record_id) {
    console.error('❌ 任务提交响应:', JSON.stringify(res))
    throw new Error(`API 错误: ${res.ret} - ${res.errmsg}`)
  }

  const historyId = res.data.aigc_data.history_record_id
  console.log(`⏳ 任务提交成功 (ID: ${historyId})，正在生成中...`)

  // 轮询
  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 2000))
    const pollRes = await request('POST', '/mweb/v1/get_history_by_ids', {
      history_ids: [historyId],
      http_common_info: { aid: 513695 },
    }, {}, token)
    const record = pollRes.data[historyId]

    if (record && record.status === 50) {
      console.log('\n🎉 生成完成！')
      const urls = record.item_list.map(item => item.image.large_images[0].image_url)
      // 优先将 p3 域名的图片排在前面 (p26 容易 403)
      return urls.sort((a, b) => {
        const aIsP3 = a.includes('p3-dreamina-sign.byteimg.com')
        const bIsP3 = b.includes('p3-dreamina-sign.byteimg.com')
        if (aIsP3 && !bIsP3)
          return -1
        if (!aIsP3 && bIsP3)
          return 1
        return 0
      })
    }
    else if (record && record.status === 30) {
      throw new Error(`生成失败，错误码: ${record.fail_code}`)
    }
    process.stdout.write('.')
  }
  throw new Error('生成超时')
}

// ================= 数据库操作 =================

// 获取或创建用户
async function getOrCreateUser(openid, sessionKey) {
  const client = await pool.connect()
  try {
    // 查找用户
    let result = await client.query('SELECT * FROM users WHERE openid = $1', [openid])
    
    if (result.rows.length > 0) {
      // 更新 session_key 和最后登录时间
      await client.query(
        'UPDATE users SET session_key = $1, last_login_at = CURRENT_TIMESTAMP WHERE id = $2',
        [sessionKey, result.rows[0].id]
      )
      return result.rows[0]
    }
    
    // 创建新用户
    const avatar = getRandomAvatar()
    result = await client.query(
      `INSERT INTO users (openid, session_key, nickname, avatar, created_at, last_login_at) 
       VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING *`,
      [openid, sessionKey, '微信用户', avatar]
    )
    
    return result.rows[0]
  } finally {
    client.release()
  }
}

// 获取用户信息
async function getUserById(userId) {
  const result = await pool.query(
    'SELECT id, openid, nickname, avatar, level, works_count, likes_count, created_at FROM users WHERE id = $1',
    [userId]
  )
  return result.rows[0]
}

// 获取用户卡券
async function getUserCoupons(userId) {
  const result = await pool.query(
    `SELECT c.*, ct.name as type_name, ct.icon, ct.color, ct.description, ct.amount
     FROM coupons c 
     JOIN coupon_types ct ON c.type_id = ct.id 
     WHERE c.user_id = $1 AND c.status = 'active' AND c.expire_at > CURRENT_TIMESTAMP
     ORDER BY c.expire_at ASC`,
    [userId]
  )
  return result.rows
}

// 创建卡券
async function createCoupon(userId, typeId, expireDays = 30) {
  const expireAt = new Date()
  expireAt.setDate(expireAt.getDate() + expireDays)
  
  await pool.query(
    `INSERT INTO coupons (user_id, type_id, status, expire_at, created_at) 
     VALUES ($1, $2, 'active', $3, CURRENT_TIMESTAMP)`,
    [userId, typeId, expireAt.toISOString()]
  )
}

// ================= API 路由 =================

// 健康检查
app.get('/health', (req, res) => {
  jsonResponse(res, { 
    code: 200, 
    msg: 'AI Poster API is running',
    data: { status: 'ok', version: '1.0.0' }
  })
})

// 微信登录
app.post('/login', async (req, res) => {
  try {
    const { code } = req.body
    
    if (!code) {
      return jsonResponse(res, { code: 400, msg: '缺少 code 参数', data: null }, 400)
    }
    
    // 调用微信接口获取 openid 和 session_key
    const wxUrl = `https://api.weixin.qq.com/sns/jscode2session?appid=${WECHAT_APPID}&secret=${WECHAT_SECRET}&js_code=${code}&grant_type=authorization_code`
    const wxRes = await axios.get(wxUrl)
    const wxData = wxRes.data
    
    if (wxData.errcode) {
      console.error('微信登录失败:', wxData)
      return jsonResponse(res, { 
        code: 400,
        msg: `微信登录失败: ${wxData.errmsg}`,
        data: null
      }, 400)
    }
    
    const { openid, session_key } = wxData
    
    // 获取或创建用户
    const user = await getOrCreateUser(openid, session_key)
    
    // 生成 Token
    const tokens = generateTokens(user.id)
    
    // 检查是否是新用户，如果是则赠送新人券
    const isNewUser = !user.last_login_at || user.last_login_at === user.created_at
    if (isNewUser) {
      await createCoupon(user.id, 1, 30) // 赠送 3 元网费券
    }
    
    jsonResponse(res, {
      code: 200,
      msg: 'success',
      data: tokens
    })
  } catch (error) {
    console.error('登录错误:', error)
    jsonResponse(res, { 
      code: 500,
      msg: error.message,
      data: null
    }, 500)
  }
})

// 刷新 Token
app.post('/auth/refreshToken', async (req, res) => {
  try {
    const { refreshToken } = req.body
    
    if (!refreshToken) {
      return jsonResponse(res, { code: 400, msg: '缺少 refreshToken', data: null }, 400)
    }
    
    const payload = decodeJWT(refreshToken, JWT_SECRET)
    if (!payload || payload.type !== 'refresh') {
      return jsonResponse(res, { code: 401, msg: '无效的 refreshToken', data: null }, 401)
    }
    
    // 生成新的 Token 对
    const tokens = generateTokens(payload.userId)
    
    jsonResponse(res, {
      code: 200,
      msg: 'success',
      data: tokens
    })
  } catch (error) {
    jsonResponse(res, { code: 500, msg: error.message, data: null }, 500)
  }
})

// 获取用户信息
app.get('/user/info', async (req, res) => {
  const payload = verifyToken(req)
  if (!payload) {
    return jsonResponse(res, { code: 401, msg: '未授权', data: null }, 401)
  }
  
  try {
    const user = await getUserById(payload.userId)
    if (!user) {
      return jsonResponse(res, { code: 404, msg: '用户不存在', data: null }, 404)
    }
    
    jsonResponse(res, {
      code: 200,
      msg: 'success',
      data: {
        userId: user.id,
        username: user.openid,
        nickname: user.nickname,
        avatar: user.avatar,
        level: user.level,
        worksCount: user.works_count,
        likesCount: user.likes_count
      }
    })
  } catch (error) {
    jsonResponse(res, { code: 500, msg: error.message, data: null }, 500)
  }
})

// 获取用户卡券
app.get('/user/coupons', async (req, res) => {
  const payload = verifyToken(req)
  if (!payload) {
    return jsonResponse(res, { code: 401, msg: '未授权', data: null }, 401)
  }
  
  try {
    const coupons = await getUserCoupons(payload.userId)
    
    jsonResponse(res, {
      code: 200,
      msg: 'success',
      data: coupons.map(c => ({
        id: c.id,
        typeName: c.type_name,
        amount: c.amount,
        icon: c.icon,
        color: c.color,
        description: c.description,
        expireAt: c.expire_at,
        status: c.status
      }))
    })
  } catch (error) {
    jsonResponse(res, { code: 500, msg: error.message, data: null }, 500)
  }
})

// 使用卡券
app.post('/user/coupons/use', async (req, res) => {
  const payload = verifyToken(req)
  if (!payload) {
    return jsonResponse(res, { code: 401, msg: '未授权', data: null }, 401)
  }
  
  try {
    const { couponId } = req.body
    
    // 验证卡券归属
    const result = await pool.query(
      'SELECT * FROM coupons WHERE id = $1 AND user_id = $2',
      [couponId, payload.userId]
    )
    
    if (result.rows.length === 0) {
      return jsonResponse(res, { code: 404, msg: '卡券不存在', data: null }, 404)
    }
    
    const coupon = result.rows[0]
    if (coupon.status !== 'active') {
      return jsonResponse(res, { code: 400, msg: '卡券已使用或已过期', data: null }, 400)
    }
    
    // 更新卡券状态
    await pool.query(
      'UPDATE coupons SET status = $1, used_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['used', couponId]
    )
    
    jsonResponse(res, {
      code: 200,
      msg: '卡券使用成功',
      data: { message: '卡券使用成功' }
    })
  } catch (error) {
    jsonResponse(res, { code: 500, msg: error.message, data: null }, 500)
  }
})

// 退出登录
app.post('/auth/logout', (req, res) => {
  jsonResponse(res, { code: 200, msg: '退出成功', data: null })
})

// 图片生成接口
app.post('/generate', upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '请上传图片' })
  }
  const prompt = req.body.prompt
  if (!prompt) {
    return res.status(400).json({ error: '请提供提示词' })
  }

  // 获取模型参数，默认使用 v40 (高速)
  const useHighQuality = req.body.highQuality === 'true' || req.body.highQuality === true
  const modelId = useHighQuality ? BLEND_MODEL_V41 : BLEND_MODEL_V40

  const filePath = req.file.path
  console.log(`收到请求: 图片=${req.file.originalname}, 提示词=${prompt}, 模型=${modelId}`)

  try {
    // 获取本次任务使用的 Token (轮询)
    const token = getNextToken()
    // console.log(`使用 Token: ${token.slice(0, 6)}...`)

    // 1. Upload
    const uri = await uploadImage(filePath, token)
    // 2. Generate
    const imageUrls = await generate(uri, prompt, token, modelId)

    // Clean up file
    fs.unlinkSync(filePath)

    res.json({ status: 'success', urls: imageUrls })
  }
  catch (e) {
    console.error('API 处理错误:', e)
    // 尝试清理文件
    if (fs.existsSync(filePath))
      fs.unlinkSync(filePath)
    res.status(500).json({ status: 'error', message: e.message })
  }
})

// ================= R2 配置 (用于视频存储) =================
const R2_ACCESS_KEY_ID = "6684b2a5b8f947ba4f6f3ba943d22439";
const R2_SECRET_ACCESS_KEY = "bd3dce5ac2df30ae34377c9ca5af26fd845abe5fa6ea179ec6810552856ca27f";
const R2_ENDPOINT = "https://67a7569d0cd89aafb7499f3cf3bc9f73.r2.cloudflarestorage.com";
const R2_BUCKET = "0926taocantoutu";
const R2_PUBLIC_PREFIX = "https://pub-c92931353257460eb0beccbf59ef2ad0.r2.dev";

// R2 Node.js 上传函数 (手动 V4 签名)
async function uploadToR2Node(filePath, fileName, contentType) {
    const fileBuffer = fs.readFileSync(filePath);
    const date = new Date();
    const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.slice(0, 8);
    const host = new URL(R2_ENDPOINT).host;
    const region = "auto";
    const service = "s3";

    const kDate = crypto.createHmac('sha256', `AWS4${R2_SECRET_ACCESS_KEY}`).update(dateStamp).digest();
    const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
    const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
    const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();

    const canonicalUri = `/${R2_BUCKET}/${fileName}`;
    const canonicalHeaders = `content-type:${contentType}\nhost:${host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
    const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
    const canonicalRequest = `PUT\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\nUNSIGNED-PAYLOAD`;
    const scope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;
    const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

    const authHeader = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    await axios.put(`${R2_ENDPOINT}/${R2_BUCKET}/${fileName}`, fileBuffer, {
        headers: {
            "Authorization": authHeader,
            "x-amz-date": amzDate,
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            "Content-Type": contentType,
        }
    });
    return `${R2_PUBLIC_PREFIX}/${fileName}`;
}

// 下载图片工具
async function downloadImage(url, dest) {
    const response = await axios({ 
      url, 
      responseType: 'arraybuffer',
      timeout: 10000 // 10s 超时
    });
    fs.writeFileSync(dest, response.data);
}

// FFmpeg 视频合成工具
const ffmpeg = require('fluent-ffmpeg');
try {
  const ffmpegStatic = require('ffmpeg-static');
  if (ffmpegStatic) ffmpeg.setFfmpegPath(ffmpegStatic);
} catch (e) {
  console.log('Using system ffmpeg instead of ffmpeg-static');
}

async function createTransitionVideo(img1, img2, outputFile) {
    const stats1 = fs.statSync(img1);
    const stats2 = fs.statSync(img2);
    console.log(`[FFmpeg] Input1: ${img1} (${stats1.size} bytes), Input2: ${img2} (${stats2.size} bytes)`);
    
    if (stats1.size === 0 || stats2.size === 0) {
        throw new Error(`Input image is empty: ${stats1.size === 0 ? img1 : img2}`);
    }

    return new Promise((resolve, reject) => {
        let stderrData = '';
        const command = ffmpeg()
            .input(img1).inputOptions(['-loop 1', '-t 3']) // 每个阶段增加到 3秒
            .input(img2).inputOptions(['-loop 1', '-t 3'])
            .complexFilter([
                // 极简滤镜：使用 480P 分辨率 (480x854) 以确保低内存环境下不崩溃
                '[0:v]scale=480:854:force_original_aspect_ratio=increase,crop=480:854,format=yuv420p[v0]',
                '[1:v]scale=480:854:force_original_aspect_ratio=increase,crop=480:854,format=yuv420p[v1]',
                // 使用 xfade 实现 1秒淡入淡出
                '[v0][v1]xfade=transition=fade:duration=1:offset=2,format=yuv420p'
            ])
            .outputOptions([
                '-preset ultrafast',
                '-r 24',
                '-pix_fmt yuv420p',
                '-threads 0',
                '-movflags +faststart'
            ]);

        command
            .on('start', (cmd) => {
                console.log('[FFmpeg] Started command:', cmd);
            })
            .on('progress', (progress) => {
                console.log(`[FFmpeg] Progress: ${progress.percent?.toFixed(2) || 0}%`);
            })
            .on('stderr', (stderrLine) => {
                stderrData += stderrLine + '\n';
                if (stderrLine.includes('Error')) console.warn('[FFmpeg Stderr]:', stderrLine);
            })
            .on('end', () => {
                console.log('[FFmpeg] Synthesis finished successfully');
                resolve(outputFile);
            })
            .on('error', (err) => {
                const detailedError = new Error(`${err.message}\n\nFFmpeg Log:\n${stderrData.slice(-1000)}`);
                console.error('[FFmpeg] Detailed Error:', detailedError.message);
                reject(detailedError);
            })
            .save(outputFile);
    });
}

// 视频生成接口
app.post('/generate-video', upload.single('image'), async (req, res) => {
  // 显式设置 CORS 响应头，防止 504 时由于中间件失效导致的 CORS 报错
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (!req.file) return res.status(400).json({ error: '请上传图片' });
  const prompt = req.body.prompt;
  if (!prompt) return res.status(400).json({ error: '请提供提示词' });

  const originalPath = req.file.path;
  const aiImagePath = path.join('uploads', `ai_${Date.now()}.png`);
  const videoOutputPath = path.join('uploads', `video_${Date.now()}.mp4`);

  try {
    const token = getNextToken();
    // 1. 生成 AI 图片
    const uri = await uploadImage(originalPath, token);
    const imageUrls = await generate(uri, prompt, token, BLEND_MODEL_V40);
    const aiImageUrl = imageUrls[0];

    // 2. 下载 AI 图片到本地以便 FFmpeg 处理
    await downloadImage(aiImageUrl, aiImagePath);

    // 3. 合成视频
    await createTransitionVideo(originalPath, aiImagePath, videoOutputPath);

    // 4. 上传视频到 R2
    const videoUrl = await uploadToR2Node(videoOutputPath, path.basename(videoOutputPath), 'video/mp4');

    // 5. 清理临时文件
    [originalPath, aiImagePath, videoOutputPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });

    res.json({ status: 'success', videoUrl: videoUrl, imageUrl: aiImageUrl });
  } catch (e) {
    console.error('视频处理错误:', e);
    [originalPath, aiImagePath, videoOutputPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// 纯视频合成接口 (复用已生成的 AI 图片)
app.post('/synthesize-video', upload.single('image'), async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (!req.file) return res.status(400).json({ error: '请上传原图' });
  const aiImageUrl = req.body.aiImageUrl;
  if (!aiImageUrl) return res.status(400).json({ error: '请提供 AI 图片 URL' });

  const originalPath = req.file.path;
  const aiImagePath = path.join('uploads', `ai_download_${Date.now()}.png`);
  const videoOutputPath = path.join('uploads', `synth_${Date.now()}.mp4`);

  try {
    console.log(`--- Synthesize Video Start: AI Image = ${aiImageUrl} ---`);
    // 1. 下载已生成的 AI 图片
    await downloadImage(aiImageUrl, aiImagePath);

    // 2. 合成转场视频
    await createTransitionVideo(originalPath, aiImagePath, videoOutputPath);

    // 3. 上传到 R2
    const videoUrl = await uploadToR2Node(videoOutputPath, path.basename(videoOutputPath), 'video/mp4');

    // 4. 清理
    [originalPath, aiImagePath, videoOutputPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });

    res.json({ status: 'success', videoUrl: videoUrl });
  } catch (e) {
    console.error('Synthesis Error:', e);
    [originalPath, aiImagePath, videoOutputPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// 调试专用：纯 FFmpeg 视频合成测试 (不调用即梦 AI)
app.post('/debug-video', upload.single('image'), async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (!req.file) return res.status(400).json({ error: '请上传图片' });
  
  const originalPath = req.file.path;
  const videoOutputPath = path.join('uploads', `debug_${Date.now()}.mp4`);

  try {
    console.log('--- Debug Video Synthesis Start ---');
    // 使用同一张图片两次来测试合成功能
    await createTransitionVideo(originalPath, originalPath, videoOutputPath);

    console.log('--- Uploading Debug Video to R2 ---');
    const videoUrl = await uploadToR2Node(videoOutputPath, path.basename(videoOutputPath), 'video/mp4');

    // 清理
    [originalPath, videoOutputPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });

    res.json({ status: 'success', videoUrl: videoUrl });
  } catch (e) {
    console.error('Debug Video Error:', e);
    if (fs.existsSync(originalPath)) fs.unlinkSync(originalPath);
    if (fs.existsSync(videoOutputPath)) fs.unlinkSync(videoOutputPath);
    res.status(500).json({ status: 'error', message: e.message, stack: e.stack });
  }
});

// 健康检查
app.get('/health', (req, res) => res.send('OK'))

// 图片代理接口 (解决 403 问题)
app.get('/proxy-image', async (req, res) => {
  const imageUrl = req.query.url
  if (!imageUrl) return res.status(400).send('Missing url')
  try {
    const response = await axios({
      url: imageUrl,
      responseType: 'stream',
      headers: { 'Referer': 'https://jimeng.jianying.com/' }
    })
    res.set('Cache-Control', 'public, max-age=31536000')
    response.data.pipe(res)
  } catch (e) {
    res.status(500).send(e.message)
  }
})

const PORT = process.env.PORT || 3000
const server = app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})

// 设置服务器超时为 5 分钟 (应对大文件合成)
server.timeout = 300000;
server.keepAliveTimeout = 300000;
