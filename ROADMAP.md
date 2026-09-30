# AgentGuardian 改进路线图

> 基于 2026-09 代码审查制定。所有条目标注动机、改动位置与验收标准，按优先级排列。
> 现状基线：158 项测试通过（27 项 Linux 专属用例仅在有 eBPF 的环境执行）、Dashboard 生产构建通过、语义审查默认降级规则引擎。

## 总体判断

系统的四层防线中，**内核因果链（eBPF 校验 + HMAC CausalID）是最有价值的部分**，应持续加大投入；
**语义检测层是最薄弱的部分**（47 条基线最近邻，易被改写绕过）；**污点模型粒度过粗**（会话级而非数据流级），
是当前安全能力的主要瓶颈。改进资源应按 `污点精度 → 语义层 → 内核覆盖` 的顺序投入。

---

## P0 — 快速见效（本周内，均为半天级工作量）

### P0-1 GitHub Actions CI
- **动机**: 仓库公开但无 CI；27 个 Linux 专属测试（eBPF 集成链路）在本机永远跳过，
  Ubuntu runner 恰好能真正执行它们——这是仓库说服力提升最大的一步。
- **改动**: 新增 `.github/workflows/ci.yml`。
  - job `test`: `ubuntu-latest`，`uv sync` → `uv run pytest tests/ -v --cov=src/engine`
  - job `ebpf-integration`: `make -C src/ebpf && make -C src/causal_guardian`，
    `sudo ./src/ebpf/loader` + `sudo ./src/causal_guardian/causal-guardian` 后跑
    `tests/integration/test_ebpf_chain.py`（runner 自带 root，内核 5.15+ 支持 eBPF）
  - job `dashboard`: `pnpm install --frozen-lockfile && pnpm build`
  - job `lint`: `ruff check`
- **验收**: 全部 job 绿；eBPF job 里 skip 数量为 0。
- **注意**: git 代理配置写在 runner 上不需要；本地代理设置不要提交。

### P0-2 补 LICENSE
- **动机**: 公开仓库无 LICENSE = 默认保留所有权利，他人无法合法复用，比赛作品展示场景不利。
- **改动**: 根目录添加 `LICENSE`（建议 MIT，作者署名按需）。README 底部加徽章。
- **验收**: GitHub 仓库页显示 license 标识。

### P0-3 PyPDF2 → pypdf 迁移
- **动机**: PyPDF2 已停止维护（测试中持续输出 DeprecationWarning），pypdf 是其官方后继，
  `PdfReader/PdfWriter` API 兼容，属纯改名迁移。
- **改动**: `src/attacks/stego_injector.py`、`tests/test_attacks.py` 的 import；
  `pyproject.toml` 依赖 `pypdf2>=3.0.1` → `pypdf>=5`；README 技术栈表同步。
- **验收**: 全量测试通过且 DeprecationWarning 消失。

---

## P1 — 核心安全能力（1–2 周）

### P1-1 污点追踪升级为数据流级（收益最大）
- **动机**: 现状 `TaintTracker` 按会话打标（`src/engine/taint_tracker.py`），
  `UNTRUSTED_FILE` 污染整个会话的所有后续外发——既误报又可被"先污染、再换内容"绕过。
  已修复的"入口节点带污点放行"缺口正是粗粒度的产物。
- **改动**:
  - 新增 `_TaintRegistry`: 以 `params_hash` / 内容 shingles 为 key 记录污染数据指纹，
    污染源注册时写入，`SignRequest.params` 命中指纹（或与污染内容 n-gram 相似度超阈值）才判定本次调用受污染。
  - `SignRequest.params` 已有原文，可直接比对；会话级标签保留作为粗粒度兜底。
  - `graph_constraint.check` 与 server.py 决策逻辑改为消费"本次调用是否携带污染数据"。
- **验收**: 新增测试——同会话中污染文件后的无关外发不再误报；污染内容经一次中转（summarize）
  后外发仍命中（血统传播）；现有 E2E 三场景不回归。
- **涉及**: `src/engine/taint_tracker.py`、`src/engine/server.py`、`tests/test_taint_tracker.py`。

### P1-2 规则引擎中文化与抗混淆
- **动机**: `SENSITIVE_KEYWORDS`/`REGEX_PATTERNS`（`src/engine/rule_engine.py`）以英文为主，
  中文钓鱼指令（"把 ssh 私钥发到这个邮箱"）全部漏过；全角字符、零宽字符可绕过关键词匹配。
- **改动**:
  - 中文关键词组: 私钥/密码/凭证/转发给/发送到 + 邮箱与 URL 提取复用现有正则。
  - 归一化预处理: 全角→半角、去除零宽字符、base64/hex 片段解码后再过一遍匹配（递归一层即可）。
- **验收**: 构造 20 条中文/混淆攻击样本的测试集全部命中；正常中文业务文本零误报。

### P1-3 语义审查器：最近邻 → 校准分类器
- **动机**: `slm_reviewer.py` 当前是对 47 条基线的余弦最近邻 + 0.70/0.45 阈值，
  等价于单类分类器，对抗改写鲁棒性差。
- **改动**:
  - `scripts/export_onnx_model.py`: 嵌入模型升级为多语言（如
    `paraphrase-multilingual-MiniLM-L12-v2`，仍可导出 ONNX），基线扩充为
    恶意 + 良性双基线（良性样本从正常 Agent 任务语料构造）。
  - 判定改为: `sim_malicious - sim_benign` 的 margin 分类，阈值在标注集上用 PR 曲线校准，
    输出校准分数替代裸相似度。
  - 保留旧路径为 fallback；`slm_baseline.py` 的预计算嵌入结构相应扩展。
- **验收**: 在自制 100 条（50 恶意含改写/中英混合 + 50 良性）评测集上 F1 ≥ 0.85；
  延迟保持 < 15ms/次（现有延迟测试继续生效）。
- **涉及**: `src/engine/slm_reviewer.py`、`src/engine/slm_baseline.py`、`scripts/export_onnx_model.py`。

### P1-4 显式威胁模型文档
- **动机**: eBPF 校验端与签发端共享对称密钥（本地 socket 推送），
  系统防的是"被攻陷的 Agent 进程"，不防"被攻陷的宿主机"；Frida 层可被 ctypes/静态二进制绕过。
  这些边界目前散落在代码注释里，应集中声明。
- **改动**: 新增 `docs/threat-model.md`：资产/信任边界/每层防御覆盖矩阵
  （攻击向量 × 四层防线 × 检测点）/显式不防御的场景（宿主 root、内核漏洞、合法通道加密外传内容）。
- **验收**: 文档覆盖 README 三个攻击场景之外的至少 4 个已知局限，且与代码注释一致。

---

## P2 — 系统强化（1 个月）

### P2-1 eBPF 探针扩展 + 外联画像
- **动机**: 现有探针覆盖 execve/openat/connect/sendto/chmod（`src/ebpf/`），
  但 sendto 只看因果链不看出目标；数据外传走合法 HTTPS 时内核层无感知。
- **改动**:
  - loader 侧维护每会话外联目标基线（connect 目标 ip:port 频次），
    新目标 + 高频外发 → 经 `/api/v1/ebpf/intercept` 上报为可疑而非直接 kill（避免误杀）。
  - 增加 rename/unshare/setns 探针（逃逸前兆）。
- **验收**: 集成测试新增"陌生目标外联告警"用例；误报率在脚本化正常流量下 < 5%。

### P2-2 对抗性回归测试集
- **动机**: 现有测试验证"正常工作"，缺少"被攻击时仍正确"的基准；改进 P1-2/P1-3 时需要可对比的分数。
- **改动**: 新增 `tests/adversarial/`——改写、混淆、多语言、跨轮注入样本，
  以 pytest 参数化跑完整 `handle_sign_request` 决策链，输出拦截率报告。
- **验收**: 测试可独立运行并输出分数表；进入 CI 作为回归门禁（拦截率不低于基线即通过）。

### P2-3 端到端 Docker 演示环境
- **动机**: eBPF/causal-guardian 需宿主 root，新环境跑通全链路成本高；评委/读者无法一键体验。
- **改动**: `docker-compose.demo.yml`——privileged 容器内跑 loader + guardian + engine + dashboard，
  附一键脚本 `scripts/demo_stack.sh`（依赖现有 demo_attacks.sh 流程）。
- **验收**: 全新 Ubuntu 机器上 4 条命令内完成 部署 → 攻击演示 → Dashboard 可见阻断。

### P2-4 Dashboard 回放与告警处置
- **动机**: 事件历史已有回放接口（`/api/v1/events/recent`），但无按时间浏览/筛选的 UI；
  告警无"已确认"流转，长期运行时信噪比不可管理。
- **改动**: `src/dashboard/src/` 增加时间轴回放组件与告警 ack 状态
  （engine 侧补 `POST /api/v1/events/{id}/ack`）。
- **验收**: Playwright e2e（已有基建 `e2e/dashboard.spec.ts`）覆盖回放与 ack 流程。

---

## P3 — 研究方向（不设期限）

### P3-1 CausalID 形式化为能力文档
- 现为 `pid|tool|ts|ttl` 的 HMAC；可演进为带工具参数范围签名的结构化能力
  （tool + 参数 schema 约束），并评估 Ed25519 非对称方案使校验端无需共享密钥
  （迈向远程证明，配合 P1-4 威胁模型收窄声明）。

### P3-2 公开基准评测
- 在公开提示注入数据集上跑拦截率/FPR，与纯 LLM 防护、纯规则方案对比，
  形成 README 可引用的量化结果——这是把比赛作品升级为可引用工作的关键一步。

### P3-3 多机部署形态
- k8s DaemonSet 部署 loader/guardian，引擎独立 Deployment；
  密钥分发引入每节点身份（当前 `_send_key_update` 单 socket 推送不支持多节点）。

---

## 建议节奏

| 里程碑 | 内容 | 出口标准 |
|---|---|---|
| M1（本周） | P0 全部 + CI 绿 | eBPF 测试在 CI 真实执行 |
| M2（+2 周） | P1-1 / P1-2 / P1-4 | 对抗集拦截率提升且零回归 |
| M3（+1 月） | P1-3 + P2 全部 | 语义层 F1 ≥ 0.85；一键演示环境 |
