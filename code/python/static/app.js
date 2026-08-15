/* ═══════════════════════════════════════════════════════════════════
   SentinelKB — AI Security Knowledge Hub
   ═══════════════════════════════════════════════════════════════════ */

const API = '/api';

const INTENT_LABELS = {
  factoid: '事实检索',
  procedural: '处置流程',
  exploratory: '关联分析',
  general: '综合问答',
};

const RISK_LABELS = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重风险',
  unchanged: '风险未变化',
};

const TACTIC_LABELS = {
  'Initial Access': '初始访问',
  Execution: '执行',
  Persistence: '持久化',
  'Privilege Escalation': '权限提升',
  'Defense Evasion': '防御规避',
  'Credential Access': '凭据访问',
  Discovery: '环境发现',
  'Lateral Movement': '横向移动',
  Collection: '信息收集',
  'Command and Control': '命令与控制',
  Exfiltration: '数据外传',
  Impact: '影响',
};

const INDICATOR_LABELS = {
  ipv4: 'IPv4 地址',
  ipv6: 'IPv6 地址',
  url: '网址',
  domain: '域名',
  cve: 'CVE 漏洞编号',
  sha256: 'SHA-256 哈希',
  md5: 'MD5 哈希',
  email: '邮箱地址',
};

const BACKEND_LABELS = {
  lexical: '本地词法检索',
  chroma: 'Chroma 向量库',
  'chroma+lexical': 'Chroma + 本地词法检索',
  pgvector: 'PGVector 向量库',
};

/* ════════════════════ State ════════════════════ */
const state = {
  uploadedDocs: [],
  asking: false,
  uploading: false,
};

/* ════════════════════ DOM refs ════════════════════ */
const $ = (s) => document.querySelector(s);

const dom = {
  statusDot: $('#statusDot'),
  statusText: $('#statusText'),
  tabs: document.querySelectorAll('.tab-btn'),
  panels: {
    qa: $('#panel-qa'),
    upload: $('#panel-upload'),
    security: $('#panel-security'),
    dashboard: $('#panel-dashboard'),
  },
  chatContainer: $('#chatContainer'),
  qaInput: $('#qaInput'),
  qaSendBtn: $('#qaSendBtn'),
  uploadZone: $('#uploadZone'),
  fileInput: $('#fileInput'),
  uploadProgress: $('#uploadProgress'),
  docList: $('#docList'),
  refreshStatsBtn: $('#refreshStatsBtn'),
  securityInput: $('#securityInput'),
  analyzeBtn: $('#analyzeBtn'),
  securityResult: $('#securityResult'),
};

/* ════════════════════ Health Check ════════════════════ */
async function checkHealth() {
  try {
    const r = await fetch(`${API}/health`);
    const d = await r.json();
    if (r.ok && d.status === 'ok') {
      dom.statusDot.classList.remove('offline');
      const modeLabel = d.mode === 'offline' ? '离线模式' : '在线模式';
      dom.statusText.textContent = `${d.service || '系统正常'} · ${modeLabel}`;
    } else {
      dom.statusDot.classList.add('offline');
      dom.statusText.textContent = `${d.service || 'SentinelKB'} · 部分组件不可用`;
    }
  } catch {
    dom.statusDot.classList.add('offline');
    dom.statusText.textContent = '服务离线';
  }
}
checkHealth();
setInterval(checkHealth, 15000);

/* ════════════════════ Tab Switching ════════════════════ */
dom.tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    dom.tabs.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    Object.values(dom.panels).forEach(p => p.classList.add('hidden'));
    dom.panels[tab].classList.remove('hidden');
    // Re-trigger fade animation
    dom.panels[tab].classList.remove('animate-fade-in-up');
    void dom.panels[tab].offsetWidth;
    dom.panels[tab].classList.add('animate-fade-in-up');
    if (tab === 'dashboard') loadStats();
  });
});

/* ════════════════════ Q&A ════════════════════ */
dom.qaSendBtn.addEventListener('click', sendQuestion);
dom.qaInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendQuestion(); }
});

async function sendQuestion() {
  const question = dom.qaInput.value.trim();
  if (!question || state.asking) return;

  state.asking = true;
  dom.qaSendBtn.disabled = true;
  dom.qaSendBtn.innerHTML = '<span class="spinner"></span>';
  dom.qaInput.value = '';

  appendMessage('user', question);

  // Show typing indicator
  const typingMsg = showTypingIndicator();

  try {
    const r = await fetch(`${API}/qa/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(formatApiError(err.detail, httpStatusMessage(r.status)));
    }
    const data = await r.json();

    // Remove typing indicator
    typingMsg.remove();

    appendMessage('agent', data.answer, {
      intent: data.intent,
      confidence: data.confidence,
      sources: data.sources,
      reasoning: data.reasoning_steps,
    });
  } catch (err) {
    typingMsg.remove();
    appendMessage('agent', `抱歉，请求失败：${err.message}`, { error: true });
  } finally {
    state.asking = false;
    dom.qaSendBtn.disabled = false;
    dom.qaSendBtn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>';
  }
}

function showTypingIndicator() {
  const div = document.createElement('div');
  div.className = 'chat-msg agent';
  div.innerHTML = `
    <div class="chat-avatar chat-avatar--agent">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
    </div>
    <div class="chat-body">
      <div class="chat-bubble chat-bubble--agent">
        <div class="typing-dots">
          <span></span><span></span><span></span>
        </div>
        <div class="typing-status">正在检索知识库并生成回答，请稍候…</div>
      </div>
    </div>
  `;
  dom.chatContainer.appendChild(div);
  dom.chatContainer.scrollTop = dom.chatContainer.scrollHeight;
  return div;
}

function appendMessage(role, content, meta) {
  const div = document.createElement('div');
  div.className = `chat-msg ${role}`;

  // Avatar
  const avatar = document.createElement('div');
  const avatarClass = role === 'user' ? 'chat-avatar--user' : 'chat-avatar--agent';
  avatar.className = `chat-avatar ${avatarClass}`;
  if (role === 'user') {
    avatar.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
  } else {
    avatar.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>';
  }

  // Body wrapper
  const body = document.createElement('div');
  body.className = 'chat-body';

  // Bubble
  const bubble = document.createElement('div');
  bubble.className = `chat-bubble chat-bubble--${role}`;

  if (meta && meta.error) {
    bubble.innerHTML = `<p style="color:var(--red-500)">${escapeHtml(content)}</p>`;
  } else {
    bubble.innerHTML = renderSafeMarkdown(content);
  }

  body.appendChild(bubble);

  // Meta tags
  if (meta) {
    const metaRow = document.createElement('div');
    metaRow.className = 'chat-meta';

    if (meta.intent) {
      const intentTag = document.createElement('span');
      intentTag.className = 'chat-tag chat-tag--intent';
      intentTag.textContent = `问答类型：${INTENT_LABELS[meta.intent] || meta.intent}`;
      metaRow.appendChild(intentTag);
    }

    if (meta.confidence > 0) {
      const confTag = document.createElement('span');
      confTag.className = 'chat-tag chat-tag--confidence';
      confTag.textContent = `回答置信度 ${(meta.confidence * 100).toFixed(0)}%`;
      metaRow.appendChild(confTag);
    }

    if (metaRow.children.length > 0) {
      body.appendChild(metaRow);
    }

    // Sources
    if (meta.sources && meta.sources.length > 0) {
      const src = document.createElement('div');
      src.className = 'chat-sources';
      src.innerHTML = '<strong>参考来源</strong> &nbsp;' +
        meta.sources.map((s, i) =>
          `[${i + 1}] ${escapeHtml(displaySourceName(s.source))}（相关度 ${(s.score * 100).toFixed(0)}%）`
        ).join(' &nbsp;·&nbsp; ');
      body.appendChild(src);
    }

    // Reasoning steps
    if (meta.reasoning && meta.reasoning.length > 0) {
      const steps = document.createElement('div');
      steps.className = 'reasoning-steps';
      meta.reasoning.forEach(step => {
        const span = document.createElement('span');
        span.className = 'reasoning-step';
        span.textContent = step;
        steps.appendChild(span);
      });
      body.appendChild(steps);
    }
  }

  div.appendChild(avatar);
  div.appendChild(body);
  dom.chatContainer.appendChild(div);

  // Smooth scroll to bottom
  dom.chatContainer.scrollTo({
    top: dom.chatContainer.scrollHeight,
    behavior: 'smooth',
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderSafeMarkdown(text) {
  const inline = value => value
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');
  const lines = escapeHtml(text).split('\n');
  const html = [];
  let listType = null;
  const closeList = () => {
    if (listType) html.push(`</${listType}>`);
    listType = null;
  };

  for (const line of lines) {
    const unordered = line.match(/^\s*[-*]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    if (unordered || ordered) {
      const nextType = unordered ? 'ul' : 'ol';
      if (listType !== nextType) {
        closeList();
        listType = nextType;
        html.push(`<${listType}>`);
      }
      html.push(`<li>${inline((unordered || ordered)[1])}</li>`);
      continue;
    }
    closeList();
    if (!line.trim()) {
      html.push('<div class="markdown-spacer"></div>');
    } else if (/^###\s+/.test(line)) {
      html.push(`<h4>${inline(line.replace(/^###\s+/, ''))}</h4>`);
    } else {
      html.push(`<p>${inline(line)}</p>`);
    }
  }
  closeList();
  return html.join('');
}

/* ════════════════════ Security Analysis ════════════════════ */
dom.analyzeBtn.addEventListener('click', analyzeSecurityEvent);

async function analyzeSecurityEvent() {
  const input = dom.securityInput.value.trim();
  if (!input) return;
  dom.analyzeBtn.disabled = true;
  dom.analyzeBtn.textContent = '研判中...';
  try {
    const response = await fetch(`${API}/security/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: input, source: '网页端手工输入' }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(formatApiError(data.detail, httpStatusMessage(response.status)));
    renderSecurityResult(data);
  } catch (err) {
    dom.securityResult.classList.remove('hidden');
    dom.securityResult.innerHTML = `<div class="security-block">研判失败：${escapeHtml(err.message)}</div>`;
  } finally {
    dom.analyzeBtn.disabled = false;
    dom.analyzeBtn.textContent = '开始研判';
  }
}

function renderSecurityResult(data) {
  const indicators = data.indicators || [];
  const techniques = data.techniques || [];
  const recommendations = data.recommendations || [];
  dom.securityResult.classList.remove('hidden');
  dom.securityResult.innerHTML = `
    <div class="risk-banner ${escapeHtml(data.severity)}">
      <div><strong>${escapeHtml(data.summary)}</strong><br><small>风险等级：${escapeHtml(riskLabel(data.severity))}</small></div>
      <div class="risk-score">${Number(data.risk_score)}/100</div>
    </div>
    <div class="security-block"><h3>IOC 指标（${indicators.length}）</h3><div class="security-tags">
      ${indicators.length ? indicators.map(item => `<span class="security-tag">${escapeHtml(INDICATOR_LABELS[item.type] || item.type)} · ${escapeHtml(item.value)}</span>`).join('') : '<span class="security-note">未发现明确威胁指标</span>'}
    </div></div>
    <div class="security-block"><h3>MITRE ATT&CK（${techniques.length}）</h3><div class="security-tags">
      ${techniques.length ? techniques.map(item => `<span class="security-tag">${escapeHtml(item.technique_id)} · ${escapeHtml(item.name)} · ${escapeHtml(TACTIC_LABELS[item.tactic] || item.tactic)}</span>`).join('') : '<span class="security-note">未匹配攻击技术</span>'}
    </div></div>
    <div class="security-block"><h3>建议处置</h3><ol class="security-list">
      ${recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
    </ol></div>`;
}

/* ════════════════════ Upload ════════════════════ */
dom.uploadZone.addEventListener('click', () => dom.fileInput.click());
dom.fileInput.addEventListener('change', () => uploadFiles(dom.fileInput.files));

dom.uploadZone.addEventListener('dragover', e => {
  e.preventDefault();
  dom.uploadZone.classList.add('drag-over');
});
dom.uploadZone.addEventListener('dragleave', () => {
  dom.uploadZone.classList.remove('drag-over');
});
dom.uploadZone.addEventListener('drop', e => {
  e.preventDefault();
  dom.uploadZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});

async function uploadFiles(fileList) {
  const files = Array.from(fileList);
  if (!files.length || state.uploading) return;

  state.uploading = true;
  dom.fileInput.disabled = true;
  dom.uploadZone.classList.add('busy');

  const progress = dom.uploadProgress;
  progress.classList.add('show');
  progress.classList.remove('error');

  for (const file of files) {
    progress.textContent = `正在处理：${file.name}…`;
    const startedAt = Date.now();
    const elapsedTimer = setInterval(() => {
      const seconds = Math.floor((Date.now() - startedAt) / 1000);
      progress.textContent = `正在处理：${file.name}（正在解析、抽取知识并写入存储，已等待 ${seconds} 秒）`;
    }, 5000);
    try {
      const form = new FormData();
      form.append('file', file);
      const r = await fetch(`${API}/ingest/upload`, { method: 'POST', body: form });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(formatApiError(err.detail, httpStatusMessage(r.status)));
      }
      const data = await r.json();
      if (data.duplicate) {
        progress.textContent = `文件已存在：${file.name}（相同内容未重复入库）`;
      } else {
        addDocToList(file.name, data);
        progress.textContent = `入库完成：${file.name}（${data.chunks_count} 个片段 · ${data.vectors_stored} 条索引 · ${data.entities_stored} 个图谱实体 · ${data.ioc_count} 个威胁指标 · ${riskLabel(data.security_risk)}）`;
      }
    } catch (err) {
      progress.textContent = `入库失败：${file.name}；${err.message}`;
      progress.classList.add('error');
    } finally {
      clearInterval(elapsedTimer);
    }
  }

  setTimeout(() => progress.classList.remove('show'), 6000);
  dom.fileInput.value = '';
  dom.fileInput.disabled = false;
  dom.uploadZone.classList.remove('busy');
  state.uploading = false;
}

function formatApiError(detail, fallback) {
  if (!detail) return fallback;
  if (typeof detail === 'string') return detail;
  if (detail.message) {
    const errors = Array.isArray(detail.errors) ? `：${detail.errors.join('；')}` : '';
    return `${detail.message}${errors}`;
  }
  return JSON.stringify(detail);
}

function httpStatusMessage(status) {
  const messages = {
    400: '请求内容不符合要求',
    401: '模型服务认证失败，请检查 API Key',
    403: '模型服务拒绝访问，请检查账户或模型权限',
    404: '请求的接口或模型不存在',
    413: '文件过大，请选择不超过 25 MB 的文件',
    422: '提交内容格式不正确',
    429: '请求过于频繁，请稍后重试',
    500: '服务内部处理失败，请查看运行终端日志',
    502: '上游模型服务暂时不可用，请稍后重试',
    503: '服务尚未准备完成，请稍后重试',
    504: '上游模型响应超时，请稍后重试',
  };
  const message = messages[status] || '请求失败';
  return `${message}（HTTP ${status}）`;
}

function displaySourceName(source) {
  const normalized = String(source || '').replaceAll('\\', '/');
  return normalized.split('/').filter(Boolean).pop() || '未知来源';
}

function riskLabel(value) {
  const key = String(value || 'low').toLowerCase();
  return RISK_LABELS[key] || value || '未知风险';
}

function addDocToList(name, data) {
  const item = document.createElement('div');
  item.className = 'doc-item';
  item.innerHTML = `
    <span class="doc-icon">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--emerald-500)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
    </span>
    <span class="doc-name">${escapeHtml(name)}</span>
    <span class="doc-meta">${data.chunks_count} 个片段 · ${data.entities_stored ?? data.entities_count ?? 0} 个实体 · ${data.ioc_count} 个威胁指标 · ${escapeHtml(riskLabel(data.security_risk))}</span>
  `;
  dom.docList.prepend(item);
  state.uploadedDocs.push({ name, data });
}

/* ════════════════════ Dashboard ════════════════════ */
async function loadStats() {
  // Reset to loading state
  ['statVectors', 'statEntities', 'statRelations', 'statBackend', 'statAnalyses', 'statIocs'].forEach(id => {
    $(`#${id}`).textContent = '...';
  });

  try {
    const r = await fetch(`${API}/admin/stats`);
    if (!r.ok) throw new Error(httpStatusMessage(r.status));
    const d = await r.json();

    animateValue($('#statVectors'), d.vector_store?.total_vectors ?? 0);
    animateValue($('#statEntities'), d.knowledge_graph?.total_entities ?? 0);
    animateValue($('#statRelations'), d.knowledge_graph?.total_relations ?? 0);
    animateValue($('#statAnalyses'), d.security?.total_analyses ?? 0);
    animateValue($('#statIocs'), d.security?.total_indicators ?? 0);

    const backendEl = $('#statBackend');
    const backend = d.vector_store?.backend;
    backendEl.textContent = BACKEND_LABELS[backend] || backend || '--';
    backendEl.style.fontSize = '18px';
    backendEl.style.fontWeight = '700';
  } catch {
    ['statVectors', 'statEntities', 'statRelations', 'statBackend', 'statAnalyses', 'statIocs'].forEach(id => {
      $(`#${id}`).textContent = '加载失败';
    });
  }
}

function animateValue(el, target) {
  const isNum = typeof target === 'number';
  if (!isNum) {
    el.textContent = target || '--';
    return;
  }
  const duration = 600;
  const start = performance.now();
  const from = 0;

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // ease-out
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(from + (target - from) * eased);
    el.textContent = current.toLocaleString();
    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

dom.refreshStatsBtn.addEventListener('click', loadStats);

/* ════════════════════ Keyboard Shortcuts ════════════════════ */
document.addEventListener('keydown', e => {
  // Ctrl+K / Cmd+K: focus QA input
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    // Switch to QA tab if not active
    const qaTab = document.querySelector('[data-tab="qa"]');
    if (!qaTab.classList.contains('active')) {
      qaTab.click();
    }
    dom.qaInput.focus();
  }

  // Escape: blur input
  if (e.key === 'Escape' && document.activeElement === dom.qaInput) {
    dom.qaInput.blur();
  }
});
