# CSL-Meter 黄金基线校准规范与原始采样归档体系 (v1.3.7)

本文档为 `CSL-Meter`（`konspace.cc`）16 款基线模型的**协议一致性校准规范**，所有参数、提示词池、端点配对及先验分布表均与引擎代码真源（`csl_engine.py` 与 `scripts/calibrate_golden_baselines.py`）逐字对齐。

## 一、基线状态声明与对外表述纪律

1. **现行代码内 `GOLDEN_BASELINES` 的真实属性**：
   - `csl_engine.GOLDEN_BASELINES` 中内置的 16 组多项分布为**未校准引擎先验值（Uncalibrated Engine Prior）**，尚未经过官方原生直连端点的 `N >= 210` 实测采样归档替换。
   - 在每个目标模型至少沉淀一份真实官方直连端点的原始采样 JSON 归档（`mode="baseline"`, `eligible_for_golden_baseline=true`, `N >= 210`）并经复核入库前，任何文档与界面均**不得将现行内置先验值称为「实测分布」**。
2. **偏离读数的对外表述边界**：
   - 当待测套餐的去偏后分布与 `GOLDEN_BASELINES` 发生偏离（或最近邻 top-1 指向其他模型家族）时，系统与报告对外统一表述为**「实测输出分布与声称模型的基线不符」**，严禁在基线完成官方直连校准前直接定性为「已证实掉包」。

## 二、与生产探针 100% 同源的采样控制变量

为保证基线校准分布与生产实测分布具备严格的统计学可比性，`scripts/calibrate_golden_baselines.py` 直接导入复用 `csl_engine` 的核心函数与常量，控制变量与生产分布探针保持 100% 同源：

| 控制变量 | 代码真源位置 | 强制参数与执行规则 | 协议一致性说明 |
| :--- | :--- | :--- | :--- |
| **出站请求函数** | `csl_engine._call_single_upstream_probe` | 直接调用引擎同一函数发起 HTTP POST | OpenAI 协议发送 `{"model": model_name, "max_tokens": 256, "temperature": 1.0, "messages": [{"role": "user", "content": prompt_text}]}`；Anthropic 协议发送同构请求体并带 `anthropic-version: 2023-06-01` |
| **采样温度 (`temperature`)** | `csl_engine.py` / `calibrate_golden_baselines.py` | 严格固定 `temperature = 1.0` | 与生产 14 发分布探针完全一致 |
| **`top_p` 参数** | 请求体不携带 `top_p` 字段（`top_p_sent = false`） | **不传 `top_p`** | 引擎请求体未传 `top_p`，校准请求体同样不传 `top_p`，保持上游默认行为一致 |
| **单次生成配额 (`max_tokens`)** | `csl_engine.py` / `calibrate_golden_baselines.py` | 所有分布探针统一固定 `max_tokens = 256` | 避免推理型模型（如 `kimi-k3.1-pro`、`deepseek-v4.1-pro`）在思考阶段耗尽配额导致正文为空（注：`max_tokens=16, temperature=0.0` 仅用于生产环境的 2 发分词/缓存计量探针，不用于分布采样） |
| **并发度 (`max_workers`)** | `ThreadPoolExecutor(max_workers=4)` | 严格固定 `4` 路并发 | 与生产分布探针一致，温和探测不触发个人/直连账号风控 |
| **提示词池 (`PROBE_PROMPTS_POOL`)** | `csl_engine.PROBE_PROMPTS_POOL` | 严格复用引擎内置的 **14 条**中英文随机整数提示词，按 `i % 14` 顺序轮转 | 校准样本数 `N` **必须为 `14` 的正整数倍**（`N = 14 × k`），确保全部 14 条提示词严格等权各执行 `k` 次，消除提示词配比漂移 |
| **数字提取器** | `csl_engine.extract_number_from_reasoning_or_content` | 直接调用引擎同一启发式提取器 | 优先提取剔除 `<think>...</think>` 后的正文 `[1, 100]` 整数；若正文为空则回退解析 `reasoning_content` / `<think>` / Anthropic `thinking` 块中的最终选定数字 |
| **样本量与运行模式 (`mode`)** | `validate_calibration_target` | `baseline` 模式强制 **`N >= 210` 且 `N % 14 == 0`**（默认 `N = 210 = 15 × 14`）；`smoke` 模式允许 `N >= 14` 且 `N % 14 == 0`，但归档标记 `eligible_for_golden_baseline = false` | 杜绝以小样本冒充正式基线构建 |
| **样本充分性硬门槛** | `run_calibration` | 有效非空数字提取样本数必须 `>= max(8, ceil(N × 8 / 14))`（对应生产单轮 `>= 8/14` 门槛）；空提取响应记录于 `empty_extraction_count`，**绝不混入 `"other"` 桶** | 若有效提取不足门槛，立即抛出 `RuntimeError("INSUFFICIENT_PROBE_CONTENT: ...")` 且零文件落盘 |
| **Token 预算硬顶** | `BATTERY_TOKEN_BUDGET_HARD_CAP = 30000` | 按用户裁决口径，每轮 14 发探针 battery 硬顶为 `30,000 tokens`；`k = N / 14` 轮总硬顶为 `k × 30,000 tokens` | 实测 `total_tokens_consumed` 超限立即抛出 `PROBE_TOKEN_BUDGET_EXCEEDED` |
| **凭证安全输入** | `--api-key-env`（默认 `CSL_CALIBRATION_API_KEY`） | **仅从环境变量读取 API Key**，不提供 `--api-key` 命令行参数 | 防止密钥进入 shell history 或 `ps` 进程参数列表；归档与标准输出零密钥留存 |

## 三、14 条标准分布探针提示词池（`csl_engine.PROBE_PROMPTS_POOL` 真源转录）

校准与生产探测共同循环使用以下 14 条提示词（`prompt_index = probe_index % 14`）：

1. `[0]` `Pick a random integer between 1 and 100. Output ONLY the digits, nothing else.`
2. `[1]` `请随机说出一个 1 到 100 之间的整数，只输出数字本身，不要任何标点或解释。`
3. `[2]` `Name one random number from 1 to 100. Reply with the integer only.`
4. `[3]` `从 1 至 100 中任选一个整数，仅返回阿拉伯数字。`
5. `[4]` `Choose a random whole number in [1, 100]. Output just the number.`
6. `[5]` `随机生成一个 1~100 的整数，只回答数字。`
7. `[6]` `Give me a single random integer between 1 and 100 (digits only).`
8. `[7]` `请立即给出一个 1 到 100 范围内的随机整数，仅输出数字。`
9. `[8]` `Select an integer at random from 1 to 100. Output only the number.`
10. `[9]` `在 1 到 100 之间盲选一个数字，只打印该数字。`
11. `[10]` `Write one random integer between 1 and 100. No words, just digits.`
12. `[11]` `随便报一个 1 到 100 以内的整数，只输出数字。`
13. `[12]` `Output a single random number between 1 and 100, digits only.`
14. `[13]` `请输出 1 到 100 之间的任意一个整数（仅限数字）。`

## 四、官方直连服务商白名单与 16 款基线模型现行内置先验值表

### 1. 官方直连端点防冒充约束

校准工具 `scripts/calibrate_golden_baselines.py` 仅允许调用以下 **10 家官方原生直连服务商**（`OFFICIAL_DIRECT_PROVIDERS`），并强制校验 `--provider` 与 `--model` 的归属配对关系；所有带壳/聚合订阅端点（`opencode`, `commandcode`, `kilo`, `cursor`, `kiro`, `copilot`）均在 `EXCLUDED_NON_DIRECT_PROVIDERS` 中显式拦截拒绝（抛出 `PROVIDER_NOT_OFFICIAL_DIRECT`）。其中 `deepseek` 官方直连端点补齐为 `https://api.deepseek.com/chat/completions`（配对 `deepseek-v4.1-pro` 与 `deepseek-v4.1-flash`）。

### 2. `csl_engine.GOLDEN_BASELINES` 现行代码内置未校准先验值表（16/16 逐字转录）

下表逐值转录自 `csl_engine.GOLDEN_BASELINES`（由 `scripts/calibrate_golden_baselines.py --self-test` 在文档存在时自动校验 16/16 完全相等；文档缺失或表不完整时自检跳过表校验并告警，不阻断自检），状态均为**未校准先验值（Uncalibrated Engine Prior）**：

| 序号 | 模型标识 (`claimed_model`) | 配对直连服务商 (`--provider`) | 官方直连端点 (`endpoint_url`) | 42 | 37 | 47 | 73 | 7 | 53 | 67 | 23 | 88 | other |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `gpt-5.6-sol` | `openai` | `https://api.openai.com/v1/chat/completions` | 0.28 | 0.22 | 0.08 | 0.16 | 0.09 | 0.04 | 0.04 | 0.04 | 0.02 | 0.03 |
| 2 | `gpt-6-astra` | `openai` | `https://api.openai.com/v1/chat/completions` | 0.25 | 0.24 | 0.09 | 0.18 | 0.08 | 0.05 | 0.03 | 0.04 | 0.01 | 0.03 |
| 3 | `gpt-5.6-luna` | `openai` | `https://api.openai.com/v1/chat/completions` | 0.34 | 0.14 | 0.06 | 0.11 | 0.16 | 0.03 | 0.03 | 0.05 | 0.03 | 0.05 |
| 4 | `claude-opus-5.5` | `anthropic` | `https://api.anthropic.com/v1/messages` | 0.11 | 0.16 | 0.31 | 0.19 | 0.05 | 0.06 | 0.04 | 0.04 | 0.01 | 0.03 |
| 5 | `claude-sonnet-5` | `anthropic` | `https://api.anthropic.com/v1/messages` | 0.13 | 0.15 | 0.29 | 0.17 | 0.06 | 0.07 | 0.05 | 0.04 | 0.01 | 0.03 |
| 6 | `claude-haiku-4.5` | `anthropic` | `https://api.anthropic.com/v1/messages` | 0.22 | 0.11 | 0.19 | 0.10 | 0.15 | 0.05 | 0.04 | 0.06 | 0.03 | 0.05 |
| 7 | `grok-4.7` | `xai` | `https://api.x.ai/v1/chat/completions` | 0.36 | 0.12 | 0.07 | 0.14 | 0.08 | 0.04 | 0.09 | 0.04 | 0.03 | 0.03 |
| 8 | `kimi-k3.1-pro` | `kimi` | `https://api.moonshot.cn/v1/chat/completions` | 0.15 | 0.26 | 0.11 | 0.21 | 0.07 | 0.05 | 0.05 | 0.03 | 0.04 | 0.03 |
| 9 | `kimi-k3` | `kimi` | `https://api.moonshot.cn/v1/chat/completions` | 0.16 | 0.25 | 0.12 | 0.20 | 0.07 | 0.05 | 0.05 | 0.03 | 0.04 | 0.03 |
| 10 | `doubao-seed-2.1-turbo` | `volcengine` | `https://ark.cn-beijing.volces.com/api/v3/chat/completions` | 0.19 | 0.18 | 0.08 | 0.12 | 0.14 | 0.06 | 0.06 | 0.05 | 0.08 | 0.04 |
| 11 | `glm-5.3` | `zhipu` | `https://open.bigmodel.cn/api/paas/v4/chat/completions` | 0.14 | 0.19 | 0.09 | 0.15 | 0.11 | 0.12 | 0.07 | 0.04 | 0.05 | 0.04 |
| 12 | `deepseek-v4.1-pro` | `deepseek` | `https://api.deepseek.com/chat/completions` | 0.17 | 0.27 | 0.13 | 0.18 | 0.06 | 0.06 | 0.04 | 0.03 | 0.03 | 0.03 |
| 13 | `deepseek-v4.1-flash` | `deepseek` | `https://api.deepseek.com/chat/completions` | 0.24 | 0.18 | 0.08 | 0.11 | 0.14 | 0.05 | 0.05 | 0.05 | 0.05 | 0.05 |
| 14 | `minimax-m3` | `minimax` | `https://api.minimax.chat/v1/text/chatcompletion_v2` | 0.18 | 0.15 | 0.10 | 0.14 | 0.12 | 0.08 | 0.08 | 0.06 | 0.05 | 0.04 |
| 15 | `qwen3.8-max` | `bailian` | `https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions` | 0.20 | 0.21 | 0.09 | 0.15 | 0.10 | 0.06 | 0.05 | 0.04 | 0.06 | 0.04 |
| 16 | `mimo-v2.6-pro` | `xiaomi` | `https://api.mimo.xiaomi.com/v1/chat/completions` | 0.21 | 0.17 | 0.10 | 0.14 | 0.11 | 0.07 | 0.06 | 0.05 | 0.05 | 0.04 |

## 五、原始采样归档结构与命令行操作指南

### 1. 归档 JSON 必含字段（逐 Probe 可复算）

每次校准运行产出的 JSON 归档文件包含以下完整证据链字段：
- `run_conditions`：`mode`（`"baseline"` 或 `"smoke"`）、`eligible_for_golden_baseline`、`provider_slug`、`claimed_model`、`sampling_model_id`、`endpoint_url`、`protocol`、`temperature` (`1.0`)、`max_tokens` (`256`)、`top_p_sent` (`false`)、`concurrency` (`4`)、`prompt_pool_size` (`14`)、`prompt_pool_sha256`、`engine_commit_sha`。基线以声称名归档，采样可用同家官方名，映射以 run_conditions 双名为准：`claimed_model` 为归档身份名（须在官方直连模型池与 `GOLDEN_BASELINES` 内），`sampling_model_id` 为实际发给 API 的采样模型名（缺省等于声称名；显式给出时须与声称名同服务商，跨家采样直接拒绝）。
- `summary_metrics`：`total_probes`、`http_ok_probes`、`http_failed_probes`、`rate_429_count`、`valid_extracted_samples`、`min_required_valid_samples`、`empty_extraction_count`、`total_elapsed_s`、`total_prompt_tokens`、`total_completion_tokens`、`total_cached_tokens`、`total_tokens_consumed`、`token_budget_hard_cap`。
- `raw_counts` 与 `measured_distribution`：仅基于有效非空提取整数统计的 10 桶原始频数与归一化概率分布。
- `comparison_with_uncalibrated_engine_prior`：与代码现行内置未校准先验分布的 `jsd_to_engine_prior` 及 `similarity_to_engine_prior_pct`。
- `extracted_tokens`：全部有效提取的数字序列列表。
- `probe_records`：长度等于 `total_probes` 的逐次探测明细数组，每项记录 `probe_index`、`prompt_index`、`prompt_text`、`ok`、`status_code`、`elapsed_ms`、`raw_text`、`had_reasoning`、`extracted_token`、`assigned_bucket`、`usage`（`prompt_tokens`/`completion_tokens`/`cached_tokens`）与 `error`。

### 2. 标准执行命令

```bash
# 1. 运行内置端到端冒烟与文档真源一致性自测（无需外网 Key）
python3 scripts/calibrate_golden_baselines.py --self-test

# 2. 正式基线校准模式（强制 N >= 210 且为 14 的倍数，默认 N = 210 = 15 x 14，API Key 走环境变量）
CSL_CALIBRATION_API_KEY="sk-..." python3 scripts/calibrate_golden_baselines.py \
  --provider kimi \
  --model kimi-k3.1-pro \
  --mode baseline \
  --samples 210 \
  --output docs/calibration_archives/kimi_k3_1_pro_baseline_210.json

# 3. 指定自定义环境变量名执行 OpenAI 官方直连基线校准（N = 210）
OPENAI_API_KEY="sk-..." python3 scripts/calibrate_golden_baselines.py \
  --provider openai \
  --model gpt-5.6-sol \
  --api-key-env OPENAI_API_KEY \
  --mode baseline \
  --samples 210 \
  --output docs/calibration_archives/gpt_5_6_sol_baseline_210.json
```
