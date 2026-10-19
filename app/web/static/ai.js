(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const base = 'https://api.luomo.moe/v1';
  function updateExample() {
    if (!$('config-code')) return;
    const model = $('config-model').value.trim() || 'gpt-6-luna';
    const quoted = JSON.stringify(model);
    const payload = JSON.stringify({model, messages: [{role: 'user', content: '你好'}], stream: false}, null, 2);
    const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";
    const examples = {
      curl: `# 先设置环境变量 LUOMO_API_KEY\ncurl ${base}/chat/completions \\\n  -H "Authorization: Bearer $LUOMO_API_KEY" \\\n  -H 'Content-Type: application/json' \\\n  -d ${shellQuote(payload)}`,
      responses: `curl ${base}/responses \\\n  -H "Authorization: Bearer $LUOMO_API_KEY" \\\n  -H 'Content-Type: application/json' \\\n  -d ${shellQuote(JSON.stringify({model, input: '你好', stream: false}, null, 2))}`,
      python: `# pip install openai\nimport os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url="${base}",\n    api_key=os.environ["LUOMO_API_KEY"],\n)\nresponse = client.chat.completions.create(\n    model=${quoted},\n    messages=[{"role": "user", "content": "你好"}],\n)\nprint(response.choices[0].message.content)`,
      javascript: `// npm install openai · 在服务端运行\nimport OpenAI from 'openai';\nconst client = new OpenAI({\n  baseURL: '${base}',\n  apiKey: process.env.LUOMO_API_KEY,\n});\nconst response = await client.chat.completions.create({\n  model: ${quoted},\n  messages: [{ role: 'user', content: '你好' }],\n});\nconsole.log(response.choices[0].message.content);`,
      airi: `提供商：OpenAI Compatible / OpenAI 兼容\nBase URL：${base}\nAPI Key：填写你自己的 LuomoAPI 密钥\n模型：${model}\n协议：Chat Completions\n\n需要权限：models:read, chat:completions\n模型白名单：${model}\n\n先保存提供商配置，再在聊天模块选择该提供商和模型。\n若测试报错，请检查 /v1 是否重复，以及密钥的权限与有效期。`
    };
    $('config-code').textContent = examples[$('config-client').value];
  }
  $('config-model')?.addEventListener('input', updateExample);
  $('config-client')?.addEventListener('change', updateExample);
  document.querySelectorAll('[data-select-model]').forEach(button => button.addEventListener('click', () => {
    $('config-model').value = button.dataset.selectModel; updateExample();
    $('configuration').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
    $('config-model').focus({preventScroll: true});
  }));
  updateExample();
  if (!$('playground-form')) return;
  let controller;
  const apiError = async response => {
    const data = await response.json().catch(() => ({}));
    return `HTTP ${response.status} · ${data.error?.message || '请求失败，请检查密钥、权限和服务状态。'}`;
  };
  $('load-models').addEventListener('click', async () => {
    const key = $('play-key').value.trim();
    if (!key) { $('model-load-status').textContent = '请先填写 API Key'; return; }
    $('load-models').disabled = true;
    try {
      const response = await fetch('/v1/models', {headers: {Authorization: `Bearer ${key}`}, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000)});
      if (!response.ok) throw new Error(await apiError(response));
      const body = await response.json();
      $('allowed-models').replaceChildren(...body.data.map(model => { const option = document.createElement('option'); option.value = model.id; return option; }));
      $('model-load-status').textContent = `已读取 ${body.data.length} 个授权模型。请选择适用于文本的模型。`;
    } catch (error) { $('model-load-status').textContent = error.message; }
    finally { $('load-models').disabled = false; }
  });
  $('play-stop').addEventListener('click', () => controller?.abort());
  $('play-clear').addEventListener('click', () => {
    controller?.abort(); $('play-key').value = ''; $('play-prompt').value = '';
    $('play-output').textContent = ''; $('play-meta').textContent = ''; $('play-status').textContent = '已清空';
    $('allowed-models').replaceChildren(); $('model-load-status').textContent = '';
  });
  window.addEventListener('pagehide', () => { controller?.abort(); $('play-key').value = ''; });
  $('playground-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (controller) return;
    controller = new AbortController();
    const timeout = setTimeout(() => controller?.abort(), 180000);
    const start = performance.now();
    $('play-send').disabled = true; $('play-stop').disabled = false;
    $('play-output').textContent = ''; $('play-meta').textContent = '';
    $('play-status').textContent = '正在连接…';
    const streamed = $('play-stream').checked;
    let usage, requestId = '', output = '';
    try {
      const response = await fetch('/v1/chat/completions', {
        method: 'POST', credentials: 'omit', cache: 'no-store', signal: controller.signal,
        headers: {'Content-Type': 'application/json', Authorization: `Bearer ${$('play-key').value.trim()}`},
        body: JSON.stringify({model: $('play-model').value.trim(), messages: [{role: 'user', content: $('play-prompt').value}], stream: streamed, ...(streamed ? {stream_options: {include_usage: true}} : {})})
      });
      requestId = response.headers.get('x-request-id') || '未返回';
      if (!response.ok) throw new Error(await apiError(response));
      if (!streamed) {
        const data = await response.json();
        if (data.error) throw new Error(data.error.message || '上游生成失败');
        output = data.choices?.[0]?.message?.content || '';
        $('play-output').textContent = output;
        usage = data.usage;
      } else {
        const reader = response.body.getReader();
        const decoder = new TextDecoder(); let pending = '', doneEvent = false, finished = false;
        const consume = eventText => {
          const raw = eventText.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
          if (!raw) return;
          if (raw === '[DONE]') { doneEvent = true; return; }
          const data = JSON.parse(raw);
          if (data.error) throw new Error(data.error.message || '流式生成失败');
          if (data.usage) usage = data.usage;
          if (data.choices?.some(choice => choice.finish_reason)) finished = true;
          output += data.choices?.[0]?.delta?.content || '';
          $('play-output').textContent = output;
          $('play-status').textContent = '正在生成…';
        };
        try {
          while (true) {
            const {value, done} = await reader.read();
            pending += decoder.decode(value, {stream: !done});
            let boundary;
            while ((boundary = /\r?\n\r?\n/.exec(pending))) { const eventText = pending.slice(0, boundary.index); pending = pending.slice(boundary.index + boundary[0].length); consume(eventText); }
            if (done) { if (pending.trim()) consume(pending); break; }
          }
          if (!doneEvent) throw new Error(finished ? '收到内容结束标记，但连接未完整结束，用量可能缺失' : '连接提前结束，回答可能不完整');
        } finally { await reader.cancel().catch(() => {}); }
      }
      $('play-status').textContent = '生成完成';
    } catch (error) {
      $('play-status').textContent = error.name === 'AbortError' ? '请求已停止或达到页面等待上限' : error.message;
    } finally {
      clearTimeout(timeout); controller = null;
      $('play-send').disabled = false; $('play-stop').disabled = true;
      $('play-meta').textContent = `${((performance.now() - start) / 1000).toFixed(1)} 秒 · 请求 ID ${requestId || '未建立'} · token ${Number.isFinite(usage?.total_tokens) ? usage.total_tokens : '未回报'}`;
    }
  });
})();
