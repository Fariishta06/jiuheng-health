/**
 * 九衡 · 健康测评平台 — EdgeOne Pages 边缘函数
 * 支持中医体质辨识 + 健康生活力画像双测评
 *
 * 由原 Node.js server.js 改写而来：
 *   - fs 读写 -> KV 存储 get/put
 *   - http.createServer -> export async function onRequest
 *   - parseBody -> await request.json()
 *   - 内存 session -> KV 存储（键名 jh_session_<token>）
 *   - Node crypto -> Web Crypto API
 *
 * ============================================================================
 * KV 存储命名空间绑定说明（重要）
 * ============================================================================
 * EdgeOne Pages 中 KV 命名空间需在控制台「项目 > KV 存储」中绑定到本项目，
 * 绑定时设置的【变量名】为：jh_kv
 * 绑定后，函数内通过全局变量 jh_kv 访问该命名空间（EdgeOne 官方约定）。
 *
 * 本函数使用的 KV 键：
 *   - jh_admins             管理员数组（JSON 字符串）
 *   - jh_keys               密钥数组（JSON 字符串）
 *   - jh_session_<token>    登录会话（JSON 字符串，{adminId, createdAt}）
 *
 * 首次请求时若 jh_admins 不存在，会自动初始化超级管理员：
 *   账号 superadmin / 密码 JH@2026sp
 * ============================================================================
 */

/* ════ CORS 头 ════ */
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

/* ════ 获取 KV 命名空间 ════ */
/**
 * EdgeOne Pages 将 KV 命名空间绑定为全局变量（变量名在控制台绑定时设定）。
 * 这里以变量名 jh_kv 为准，并兼容 env.jh_kv 的回退方式，确保稳健。
 */
function getKV(env) {
  // 优先：全局变量（EdgeOne 官方文档约定的访问方式）
  if (typeof globalThis !== 'undefined' && globalThis.jh_kv) return globalThis.jh_kv;
  try {
    if (typeof jh_kv !== 'undefined' && jh_kv) return jh_kv; // eslint-disable-line no-undef
  } catch (e) { /* 未定义则忽略 */ }
  // 回退：通过 env 绑定访问
  if (env && env.jh_kv) return env.jh_kv;
  return null;
}

/* ════ 数据存储（KV） ════ */
async function getAdmins(kv) {
  const raw = await kv.get('jh_admins');
  if (raw === null || raw === undefined) {
    // 首次初始化超级管理员
    const admins = [{
      id: 'admin_super',
      username: 'superadmin',
      password: 'JH@2026sp',
      nickname: '超级管理员',
      role: 'super',
      dailyLimit: -1,
      frozen: false,
      createdAt: new Date().toISOString(),
      operations: []
    }];
    await kv.put('jh_admins', JSON.stringify(admins));
    return admins;
  }
  try { return JSON.parse(raw); } catch { return []; }
}

async function saveAdmins(kv, admins) {
  await kv.put('jh_admins', JSON.stringify(admins));
}

async function getKeys(kv) {
  const raw = await kv.get('jh_keys');
  if (raw === null || raw === undefined) return [];
  try { return JSON.parse(raw); } catch { return []; }
}

async function saveKeys(kv, keys) {
  await kv.put('jh_keys', JSON.stringify(keys));
}

/* ════ 工具函数（Web Crypto API） ════ */
function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function genId(prefix) {
  return prefix + '_' + Date.now() + '_' + randomHex(3);
}

function genKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return 'JH-' + seg() + '-' + seg();
}

function genPwd() {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function sendJSON(code, data) {
  return new Response(JSON.stringify(data), {
    status: code,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders
    }
  });
}

async function parseBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

/* ════ Session 管理（KV 存储） ════ */
async function createSession(kv, adminId) {
  const token = randomHex(16);
  await kv.put('jh_session_' + token, JSON.stringify({ adminId, createdAt: Date.now() }));
  return token;
}

async function getSessionAdmin(kv, request, admins) {
  const auth = request.headers.get('authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const raw = await kv.get('jh_session_' + token);
  if (!raw) return null;
  let session;
  try { session = JSON.parse(raw); } catch { return null; }
  // session 24小时过期
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    await kv.delete('jh_session_' + token);
    return null;
  }
  return admins.find(a => a.id === session.adminId) || null;
}

/**
 * 鉴权：返回 { admin } 或 { error: Response }
 * 调用方：const auth = await requireAuth(kv, request); if (auth.error) return auth.error;
 */
async function requireAuth(kv, request, admins) {
  const admin = await getSessionAdmin(kv, request, admins);
  if (!admin) return { error: sendJSON(401, { error: '未登录或会话已过期' }) };
  return { admin };
}

/* ════ 路由处理 ════ */
async function handleAPI(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  const kv = getKV(env);
  if (!kv) {
    return sendJSON(500, { error: 'KV 存储未绑定，请在 EdgeOne 控制台绑定变量名为 jh_kv 的 KV 命名空间' });
  }

  /* ── 管理员登录 ── */
  if (pathname === '/api/login' && method === 'POST') {
    const body = await parseBody(request);
    const admins = await getAdmins(kv);
    const admin = admins.find(a => a.username === body.username && a.password === body.password && !a.frozen);
    if (!admin) return sendJSON(401, { error: '账号或密码错误，或账号已被冻结' });
    const token = await createSession(kv, admin.id);
    return sendJSON(200, {
      token,
      admin: {
        id: admin.id, username: admin.username, nickname: admin.nickname,
        role: admin.role, dailyLimit: admin.dailyLimit, frozen: admin.frozen
      }
    });
  }

  /* ── 验证 token ── */
  if (pathname === '/api/me' && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    return sendJSON(200, {
      id: admin.id, username: admin.username, nickname: admin.nickname,
      role: admin.role, dailyLimit: admin.dailyLimit, frozen: admin.frozen
    });
  }

  /* ── 修改密码（仅超级管理员） ── */
  if (pathname === '/api/change-password' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可修改密码' });
    const body = await parseBody(request);
    if (body.oldPassword !== admin.password) return sendJSON(400, { error: '当前密码不正确' });
    if (!body.newPassword || body.newPassword.length < 6) return sendJSON(400, { error: '新密码至少6位' });
    admin.password = body.newPassword;
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ── 修改昵称 ── */
  if (pathname === '/api/update-nickname' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    const body = await parseBody(request);
    if (!body.nickname) return sendJSON(400, { error: '昵称不能为空' });
    admin.nickname = body.nickname;
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ════ 密钥相关 ════ */

  /* ── 客户端：验证密钥 ── */
  if (pathname === '/api/keys/validate' && method === 'POST') {
    const body = await parseBody(request);
    const keyStr = (body.key || '').trim().toUpperCase();
    if (!keyStr) return sendJSON(400, { error: '请输入密钥' });
    const keys = await getKeys(kv);
    const key = keys.find(k => k.key === keyStr);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    if (key.status === 'disabled') return sendJSON(400, { error: '该密钥已停用' });
    if (key.isMember && key.memberExpiresAt && new Date(key.memberExpiresAt) < new Date()) {
      return sendJSON(400, { error: '会员已过期，请联系管理员' });
    }
    return sendJSON(200, {
      id: key.id, key: key.key, isMember: key.isMember, isTest: key.isTest,
      memberExpiresAt: key.memberExpiresAt,
      status: key.status,
      vitalityStatus: key.vitalityStatus || 'unused',
      hasConstitutionResult: (key.results || []).length > 0,
      hasVitalityResult: (key.vitalityResults || []).length > 0
    });
  }

  /* ── 客户端：提交测评结果 ── */
  if (pathname === '/api/keys/result' && method === 'POST') {
    const body = await parseBody(request);
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === body.keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    if (key.status === 'disabled') return sendJSON(400, { error: '密钥已停用' });

    const type = body.type || 'constitution'; // 'constitution' 或 'vitality'
    const result = {
      date: new Date().toISOString(),
      type: type
    };

    if (type === 'constitution') {
      result.scores = body.scores;
      result.mainType = body.mainType;
      result.mainScore = body.mainScore;
      result.pingheResult = body.pingheResult;
      result.biasedResults = body.biasedResults;
      result.secondaryTypes = body.secondaryTypes || [];
      result.gender = body.gender;

      if (!key.isTest) {
        key.results = key.results || [];
        key.results.unshift(result);
        if (!key.isMember) key.status = 'completed';
      }
    } else if (type === 'vitality') {
      result.totalScore = body.totalScore;
      result.dimScores = body.dimScores;         // [6个分数]
      result.topDims = body.topDims;             // ['饮食','睡眠',...]
      result.chosenGoal = body.chosenGoal;       // 用户选择的目标
      result.profileData = body.profileData;     // 前置问卷数据
      result.statusText = body.statusText;

      if (!key.isTest) {
        key.vitalityResults = key.vitalityResults || [];
        key.vitalityResults.unshift(result);
        if (!key.isMember) key.vitalityStatus = 'completed';
      }
    }

    await saveKeys(kv, keys);
    return sendJSON(200, { ok: true, result });
  }

  /* ── 客户端：获取历史结果 ── */
  if (pathname.startsWith('/api/keys/') && pathname.endsWith('/results') && method === 'GET') {
    const keyId = pathname.split('/')[3];
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    return sendJSON(200, {
      results: key.results || [],
      vitalityResults: key.vitalityResults || [],
      key: { id: key.id, key: key.key, isMember: key.isMember, isTest: key.isTest, memberExpiresAt: key.memberExpiresAt }
    });
  }

  /* ── 以下接口需要管理员登录 ── */

  /* ── 生成密钥 ── */
  if (pathname === '/api/keys/generate' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;

    // 检查权限和限额
    if (admin.role === 'sub') {
      if (admin.frozen) return sendJSON(403, { error: '账号已冻结' });
      if (admin.dailyLimit > 0) {
        const keys = await getKeys(kv);
        const today = new Date().toDateString();
        const todayCount = keys.filter(k => k.createdBy === admin.id && new Date(k.createdAt).toDateString() === today && !k.isTest).length;
        if (todayCount >= admin.dailyLimit) return sendJSON(403, { error: `今日生成已达上限（${admin.dailyLimit}个）` });
      }
    }

    const body = await parseBody(request);
    const isTest = body.isTest && admin.role === 'super'; // 只有超级管理员能生成测试密钥

    const newKey = {
      id: genId('key'),
      key: genKey(),
      createdBy: admin.id,
      createdByNickname: admin.nickname || admin.username,
      remark: body.remark || '',
      status: 'unused',          // 体质测评状态
      vitalityStatus: 'unused',  // 生活力测评状态
      isMember: false,
      isTest: isTest,
      createdAt: new Date().toISOString(),
      memberExpiresAt: null,
      results: [],               // 体质测评结果
      vitalityResults: []        // 生活力测评结果
    };

    const keys = await getKeys(kv);
    keys.push(newKey);

    // 记录操作日志
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: isTest ? '生成测试密钥' : '生成密钥', detail: newKey.key + (body.remark ? ' ' + body.remark : ''), time: new Date().toISOString() });

    await saveKeys(kv, keys);
    await saveAdmins(kv, admins);
    return sendJSON(200, newKey);
  }

  /* ── 获取密钥列表 ── */
  if (pathname === '/api/keys' && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;

    let keys = await getKeys(kv);

    // 筛选
    const adminFilter = url.searchParams.get('adminId');
    const statusFilter = url.searchParams.get('status');
    const search = (url.searchParams.get('search') || '').toUpperCase();

    if (adminFilter) keys = keys.filter(k => k.createdBy === adminFilter);
    if (statusFilter) {
      if (statusFilter === 'member') keys = keys.filter(k => k.isMember);
      else if (statusFilter === 'test') keys = keys.filter(k => k.isTest);
      else keys = keys.filter(k => k.status === statusFilter);
    }
    if (search) keys = keys.filter(k => k.key.includes(search) || (k.remark && k.remark.toUpperCase().includes(search)));

    // 按创建时间倒序
    keys = keys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    // 脱敏：只返回必要字段
    const result = keys.map(k => ({
      id: k.id, key: k.key, createdBy: k.createdBy, createdByNickname: k.createdByNickname,
      remark: k.remark, status: k.status, isMember: k.isMember, isTest: k.isTest,
      createdAt: k.createdAt, memberExpiresAt: k.memberExpiresAt,
      latestResult: (k.results && k.results[0]) ? { mainType: k.results[0].mainType, date: k.results[0].date } : null,
      resultCount: (k.results || []).length,
      vitalityStatus: k.vitalityStatus || 'unused',
      latestVitalityResult: (k.vitalityResults && k.vitalityResults[0]) ? { chosenGoal: k.vitalityResults[0].chosenGoal, totalScore: k.vitalityResults[0].totalScore, date: k.vitalityResults[0].date } : null,
      vitalityResultCount: (k.vitalityResults || []).length
    }));

    return sendJSON(200, { keys: result });
  }

  /* ── 获取密钥详情 ── */
  if (pathname.startsWith('/api/keys/') && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const keyId = pathname.split('/')[3];
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    return sendJSON(200, key);
  }

  /* ── 解锁/取消会员 ── */
  if (pathname === '/api/keys/member' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    const body = await parseBody(request);
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === body.keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });

    // 权限检查：只有创建者和超级管理员可操作
    if (key.createdBy !== admin.id && admin.role !== 'super') {
      return sendJSON(403, { error: '无权操作此密钥' });
    }

    if (body.unlock) {
      const expiresAt = new Date();
      expiresAt.setMonth(expiresAt.getMonth() + 1);
      key.isMember = true;
      key.memberExpiresAt = expiresAt.toISOString();
    } else {
      key.isMember = false;
      key.memberExpiresAt = null;
    }

    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: body.unlock ? '解锁会员' : '取消会员', detail: key.key, time: new Date().toISOString() });
    await saveKeys(kv, keys);
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true, key });
  }

  /* ── 编辑备注 ── */
  if (pathname === '/api/keys/remark' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    const body = await parseBody(request);
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === body.keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    if (key.createdBy !== admin.id && admin.role !== 'super') {
      return sendJSON(403, { error: '无权操作此密钥' });
    }
    key.remark = body.remark || '';
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: '编辑备注', detail: key.key + ' ' + key.remark, time: new Date().toISOString() });
    await saveKeys(kv, keys);
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ── 停用/恢复密钥 ── */
  if (pathname === '/api/keys/disable' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    const body = await parseBody(request);
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === body.keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    if (key.createdBy !== admin.id && admin.role !== 'super') {
      return sendJSON(403, { error: '无权操作此密钥' });
    }
    key.status = body.disable ? 'disabled' : 'unused';
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: body.disable ? '停用密钥' : '恢复密钥', detail: key.key, time: new Date().toISOString() });
    await saveKeys(kv, keys);
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ── 删除密钥（仅超级管理员） ── */
  if (pathname === '/api/keys/delete' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可删除密钥' });
    const body = await parseBody(request);
    const keys = await getKeys(kv);
    const key = keys.find(k => k.id === body.keyId);
    if (!key) return sendJSON(404, { error: '密钥不存在' });
    const newKeys = keys.filter(k => k.id !== body.keyId);
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: '删除密钥', detail: key.key, time: new Date().toISOString() });
    await saveKeys(kv, newKeys);
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ── 数据看板 ── */
  if (pathname === '/api/dashboard' && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const startStr = url.searchParams.get('start');
    const endStr = url.searchParams.get('end');
    let keys = await getKeys(kv);
    if (startStr && endStr) {
      const start = new Date(startStr + 'T00:00:00');
      const end = new Date(endStr + 'T23:59:59');
      keys = keys.filter(k => {
        const d = new Date(k.createdAt);
        return d >= start && d <= end;
      });
    }
    return sendJSON(200, {
      totalGen: keys.filter(k => !k.isTest).length,
      totalUnlock: keys.filter(k => k.isMember).length,
      totalCompleted: keys.filter(k => k.status === 'completed').length,
      totalTest: keys.filter(k => k.isTest).length
    });
  }

  /* ════ 子管理员管理 ════ */

  /* ── 获取管理员列表 ── */
  if (pathname === '/api/admins' && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const result = admins.map(a => ({
      id: a.id, username: a.username, nickname: a.nickname, role: a.role,
      dailyLimit: a.dailyLimit, frozen: a.frozen, createdAt: a.createdAt,
      operations: (a.operations || []).slice(0, 10),
      operationStats: {
        genCount: (a.operations || []).filter(o => o.action.includes('生成')).length,
        unlockCount: (a.operations || []).filter(o => o.action.includes('解锁会员')).length
      }
    }));
    return sendJSON(200, { admins: result });
  }

  /* ── 新增子管理员 ── */
  if (pathname === '/api/admins' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可新增子管理员' });
    const body = await parseBody(request);
    if (!body.username || !/^[a-zA-Z0-9_]+$/.test(body.username)) return sendJSON(400, { error: '账号格式不正确' });
    if (!body.nickname) return sendJSON(400, { error: '请输入昵称' });
    if (admins.some(a => a.username === body.username)) return sendJSON(400, { error: '账号已存在' });

    const password = genPwd();
    const newAdmin = {
      id: genId('admin'),
      username: body.username,
      password: password,
      nickname: body.nickname,
      role: 'sub',
      dailyLimit: parseInt(body.dailyLimit) || 20,
      frozen: false,
      createdAt: new Date().toISOString(),
      operations: []
    };
    admins.push(newAdmin);
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: '新增子管理员', detail: body.username + ' ' + body.nickname, time: new Date().toISOString() });
    await saveAdmins(kv, admins);
    return sendJSON(200, { admin: { ...newAdmin, password } }); // 返回密码仅此一次
  }

  /* ── 更新管理员（限额、冻结等） ── */
  if (pathname === '/api/admins/update' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可操作' });
    const body = await parseBody(request);
    const target = admins.find(a => a.id === body.adminId);
    if (!target) return sendJSON(404, { error: '管理员不存在' });

    if (body.dailyLimit !== undefined) target.dailyLimit = body.dailyLimit;
    if (body.frozen !== undefined) target.frozen = body.frozen;

    admin.operations = admin.operations || [];
    if (body.frozen !== undefined) {
      admin.operations.unshift({ action: body.frozen ? '冻结子管理员' : '恢复子管理员', detail: target.username, time: new Date().toISOString() });
    }
    if (body.dailyLimit !== undefined) {
      admin.operations.unshift({ action: '设置限额', detail: target.username + ' ' + (body.dailyLimit < 0 ? '不限' : body.dailyLimit + '个/日'), time: new Date().toISOString() });
    }
    await saveAdmins(kv, admins);
    return sendJSON(200, { ok: true });
  }

  /* ── 重置密码 ── */
  if (pathname === '/api/admins/reset-pwd' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可操作' });
    const body = await parseBody(request);
    const target = admins.find(a => a.id === body.adminId);
    if (!target) return sendJSON(404, { error: '管理员不存在' });
    const password = genPwd();
    target.password = password;
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: '重置密码', detail: target.username, time: new Date().toISOString() });
    await saveAdmins(kv, admins);
    return sendJSON(200, { password });
  }

  /* ── 删除子管理员 ── */
  if (pathname === '/api/admins/delete' && method === 'POST') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const admin = auth.admin;
    if (admin.role !== 'super') return sendJSON(403, { error: '仅超级管理员可操作' });
    const body = await parseBody(request);
    const target = admins.find(a => a.id === body.adminId);
    if (!target) return sendJSON(404, { error: '管理员不存在' });
    admin.operations = admin.operations || [];
    admin.operations.unshift({ action: '删除子管理员', detail: target.username, time: new Date().toISOString() });
    const newAdmins = admins.filter(a => a.id !== body.adminId);
    await saveAdmins(kv, newAdmins);
    return sendJSON(200, { ok: true });
  }

  /* ── 获取管理员操作记录 ── */
  if (pathname.startsWith('/api/admins/') && pathname.endsWith('/operations') && method === 'GET') {
    const admins = await getAdmins(kv);
    const auth = await requireAuth(kv, request, admins);
    if (auth.error) return auth.error;
    const adminId = pathname.split('/')[3];
    const target = admins.find(a => a.id === adminId);
    if (!target) return sendJSON(404, { error: '管理员不存在' });
    return sendJSON(200, { operations: target.operations || [] });
  }

  /* 404 */
  return sendJSON(404, { error: '接口不存在' });
}

/* ════ 边缘函数入口 ════ */
export async function onRequest({ request, env }) {
  // CORS 预检
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    return await handleAPI(request, env);
  } catch (e) {
    return sendJSON(500, { error: '服务器内部错误', detail: String(e && e.message || e) });
  }
}
