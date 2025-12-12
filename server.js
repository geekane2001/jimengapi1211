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

const app = express()
app.use(cors())
const upload = multer({ dest: 'uploads/' })

// ================= 配置区域 =================
// 默认 Token，也可通过环境变量 JIMENG_TOKEN 传入 (支持逗号分隔的多账号轮询)
const JIMENG_TOKENS = (process.env.JIMENG_TOKEN || '304d66838b09f810b70e2c14a81978f9').split(',').map(t => t.trim()).filter(t => t)
const BLEND_MODEL_V40 = 'high_aes_general_v40' // 4.0 版本 (高速)
const BLEND_MODEL_V41 = 'high_aes_general_v41' // 4.1 版本 (高质量)
let currentTokenIndex = 0

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

// ================= API 路由 =================
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

app.get('/health', (req, res) => res.send('OK'))

// 图片代理接口 (解决 403 问题)
app.get('/proxy-image', async (req, res) => {
  const imageUrl = req.query.url
  if (!imageUrl) {
    return res.status(400).send('Missing url parameter')
  }

  try {
    const response = await axios({
      method: 'GET',
      url: imageUrl,
      responseType: 'stream',
      headers: {
        'Referer': 'https://jimeng.jianying.com/', // 伪造 Referer
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      },
    })

    // 透传 Content-Type
    res.set('Content-Type', response.headers['content-type'])
    // 缓存控制
    res.set('Cache-Control', 'public, max-age=31536000')

    response.data.pipe(res)
  }
  catch (error) {
    console.error('Proxy error:', error.message)
    res.status(500).send('Proxy error')
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
