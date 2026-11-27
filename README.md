<p align="center">
  <img src="assets/logo.png" width="160" height="160" alt="AI-智能广告杀手 Logo" />
</p>

<h1 align="center">AI-智能广告杀手 v0.2.0</h1>

<p align="center">
  <strong>开源自托管、全模型通用、傻瓜式管理的 Telegram AI 反广告守卫</strong><br/>
  一行 Bash 零门槛部署 · 任意 OpenAI 兼容单模型自动探测多模态识图 · 拉群发 <code>/config</code> 点按钮即用
</p>

---

## 🚀 1 分钟快速安装（免 `nano` 编辑）

### 一行 Bash 全自动安装并启动（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/judy-gotv/AdKiller-AI/main/setup.sh)
```

> **手动克隆安装**：`git clone https://github.com/judy-gotv/AdKiller-AI.git && cd AdKiller-AI && bash setup.sh`

### 安装前准备两样东西
1. **Bot Token**：在 Telegram 找 `@BotFather` 发 `/newbot` 获取 `TELEGRAM_BOT_TOKEN`，并顺手发 `/setprivacy` → 选中你的 Bot → `Disable`（关闭隐私模式，否则机器人读不到群消息）。
2. **你的纯数字 User ID（`OWNER_IDS`，注意不是 `@用户名`）**：私聊 `@userinfobot` 或 `@MissRose_bot` 发 `/id` 即可复制。
   * *(可选 · 防陌生人拉群)* 拉进自己群后，可在 `@BotFather` 发 `/setjoingroups` → `Disable`。

### 跟着向导 30 秒跑起来
1. **自动配置与建站**：向导自动拉取代码，隐藏回显输入 **Bot Token**（自动反查并打印 `https://t.me/<username>` 直达链接）与 **超管 ID**，可选一键把机器人换上**AI-智能广告杀手官方头像、名称与简介**，以 `600` 权限生成 `.env`、注册全局终端命令 **`adkiller`** 并构建启动 Docker 容器。
2. **配置 AI 接口与 API Key（随时热更新，不填也能跑）**：
   * **方式 A（推荐 · 私聊点按钮）**：私聊你的机器人发 `/start` → 点 **`🤖 配置 AI 接口 / API Key`** → 选服务商预设或自定义地址 → 填入 API Key，**立即热生效并自动探测多模态识图**，无需重启容器。
   * **方式 B（终端填写）**：在 `setup.sh` 第 3 步直接填写，或随时运行 `adkiller config`；若手动修改了 `.env`，执行 `adkiller restart`（内部使用 `docker compose up -d --force-recreate adkiller`）即可重新加载最新环境变量。
   * **零 Key 硬防模式**：暂不填 API Key 时默认运行保守低误杀的本地硬防（CAS 黑库 / 分层防刷屏 / 木马拦截 / 入群验证 / 应急反炸群 / 群友 `/spam` 举报）。
3. **拉进群设为管理员**：勾选 **删除消息**、**封禁用户**（如需开启入群验证或灰区禁言，请保留限制成员权限）。机器人进群后会自动发一张**AI-智能广告杀手入场报到图**，并自动注册分层 `/` 指令提示菜单；群内发 `/config`（完整支持**匿名群管**与**本群关联频道**；多匿名管修改文案时自动转至个人私聊输入以防串改）即可点按钮开关全部防护。

<details>
<summary>常见 OpenAI 兼容模型预设参考（任意中转皆可用 · 无需超长上下文）</summary>

| 服务商 | `AI_BASE_URL` | 推荐 `AI_MODEL` | 多模态识图 |
| --- | --- | --- | --- |
| **DeepSeek（高性价比推荐）** | `https://api.deepseek.com/v1` | `deepseek-flash` | ✅ 原生支持 |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-5-mini` / `gpt-4.1-mini` | ✅ 原生支持 |
| **Gemini（OpenAI 兼容）** | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-2.5-flash` | ✅ 原生支持 |
| **OpenRouter / New API / Ollama 等** | 填中转或本机 `/v1` 地址 | 填任意模型名 | 自动探测 |

> **💡 关于上下文长度与 Token 消耗**：AI-智能广告杀手采用**无状态单次判别**（不会把整群历史聊天越滚越长），实测单次审核输入仅约 **1.2K～2K tokens**（且静态 System Prompt 吃满 Prefix KV Cache，命中率约 65%～70%）。因此**不需要追求 200K / 1M 超长上下文模型**——任意 **8K～128K 上下文**的轻量快模型即完全足够；云端模型也绝不会触发长上下文阶梯加价；本地 Ollama / vLLM 自部署可把上下文开在 `8K～16K` 节省显存。

</details>

<details>
<summary>🔄 从旧版安装迁移（保留 <code>.env</code> 与 <code>data/</code>）</summary>

旧版安装在 `/opt/shieorange`、数据库为 `data/shieorange.db`。按下面步骤无损迁移（**完整保留原 `.env` 密钥与历史数据**）：

```bash
# 1. 停止旧容器并备份 .env 与 data/
cd /opt/shieorange && docker compose down
mkdir -p /tmp/adkiller_bak
cp -a /opt/shieorange/.env /opt/shieorange/data /tmp/adkiller_bak/

# 2. 从本仓库全新克隆，并还原 .env 与 data/（数据库文件改名为新名字）
cd /opt && mv shieorange shieorange.old
git clone https://github.com/judy-gotv/AdKiller-AI.git AdKiller-AI
cp -a /tmp/adkiller_bak/.env /opt/AdKiller-AI/
mkdir -p /opt/AdKiller-AI/data
cp -a /tmp/adkiller_bak/data/shieorange.db /opt/AdKiller-AI/data/adkiller.db
chmod 600 /opt/AdKiller-AI/.env

# 3. 刷新终端快捷命令并重建启动（此后即可直接使用 adkiller update）
cd /opt/AdKiller-AI
bash setup.sh --install-cli
docker compose up -d --build --force-recreate
```
确认运行正常后，再手动清理 `/tmp/adkiller_bak` 与 `/opt/shieorange.old`。

</details>

### 终端快捷管理命令 `adkiller`
安装完成后，在服务器任意目录直接输入 **`adkiller`** 即可打开交互式管理菜单：
* `adkiller` — 打开主菜单（预览运行状态、守护群数、直达链接、模型来源与快捷操作）
* `adkiller status` — 查看运行状态总览 + 子菜单（**广告击杀明细 / 疑似排查 / 模型与 Token 汇报**）
* `adkiller config` — 重新进入交互式配置向导
* `adkiller brand` — 一键把机器人换上AI-智能广告杀手官方头像、名称与简介
* `adkiller update` — 拉取最新版本并自动重建重启
* `adkiller restart` — 重建并重启容器（自动重新加载修改后的 `.env` 环境变量）
* `adkiller logs` / `stop` — 实时日志 / 停止服务

---

## 🔒 数据存储与隐私边界

* **数据存在哪里（本机 SQLite）**：所有群配置、白名单、封禁/禁言记录、统计计数与私聊录入的模型配置均保存在你服务器的本地 `data/adkiller.db` 中；AI-智能广告杀手本身不设任何官方云端、中转服务器或遥测上报。
* **外部请求发给谁（按实际开启的功能）**：
  * **AI 语义 / 识图审核**（填入 `AI_API_KEY` 后启用）：待审消息摘要、近期群聊上下文及必要时的图片/贴纸缩略图会发往**你自己配置的模型 API 地址（`AI_BASE_URL`）**，受对应模型服务商的隐私政策约束。若希望聊天内容完全不出内网，可将 `AI_BASE_URL` 指向本机/内网自部署 OpenAI 兼容服务（如 Ollama / vLLM），或留空 `AI_API_KEY` 仅启用本地硬防。
  * **CAS 全球黑库查询**（默认开启，可在 `/config` 随时关闭）：新成员入群或首次发言时，会向 `api.cas.chat` 查询该账号的纯数字 User ID（不发送任何聊天消息内容）。

---

## ✨ 核心特点

### 1. 开箱即用，无 AI 也能防，有 AI 更强
* **本地硬防 + AI 语义分层协同**：不填 `AI_API_KEY` 或上游故障时自动维持本地硬防护；**本地关键词规则默认关闭**（避免中文多义词误伤，接入 AI 后全交语义判别，也支持在 `/config` 单群一键按需开启）。
* **单模型全兼容 + 自动探测多模态**：启动或更换 Key 时自动发测试图探测——支持识图则自动开启图片/贴纸/视频缩略图反广告，不支持则清晰提示并自动降级为纯文本 + 全载体透视模式。
* **一键品牌化 & 入场仪式感**：支持在安装向导、`adkiller brand` 或私聊 `/start` 一键设置AI-智能广告杀手满圆头像、名称与简介（亦支持上传自定义图片/文案）；机器人进群自动发送AI-智能广告杀手入场报到图。
* **多维度运行状态与 AI 战报**：Linux 终端 `adkiller status` 与 Telegram 私聊 `/start` → **📊 运行状态与战报** 双端同步，实时查看守护群数、今日/累计击杀详情（命中方式 + 理由）、疑似灰区与复读排查、以及模型引擎/缓存命中/Token 消耗汇报。
* **安全权限隔离 & 防陌生人白嫖**：
  * **默认开启「🔒 仅超管可拉群」**：非超管（`OWNER_IDS`）将机器人拉入陌生新群时自动 `leave_chat` 退群并私聊告警超管（0 Token 消耗），也可在私聊 `/start` 一键切换，或搭配 `.env` 的 `ALLOWED_GROUP_IDS` / `@BotFather` `/setjoingroups -> Disable` 双重锁定；
  * `.env` 的 `OWNER_IDS` 优先级最高；留空时通过启动日志一次性 15 分钟 `/claim <口令>` 认领（防抢注）；完整支持**群匿名管理员**与**关联频道**唤出面板（当群内存在多位匿名管理员时，文本配置输入会自动引导至个人私聊，避免互相串改）；所有按钮操作均实时核验真实管理员权限，撤职即撤销私聊日志订阅。

### 2. 全维度反绕过防线
* **全载体透视**：自动剥出 **隐形超链接 (`text_link`)、网页预览隐藏链、内联按钮链接、外部内联机器人 (`via @xxxbot`)、分享联系人名片 (`contact` 含 vCard)、地点卡片、语音/视频圈、外部引用、转发来源、频道马甲、投票 (`poll`)、转发动态 (`story`)、付费媒体 (`paid_media`)、发件人 Bio 与主页个人频道简介**。
* **字符反混淆 & 混淆引流昵称识别**：自动剥离正文零宽隐形字符（`\u200b` 等）并做 Unicode NFKC 还原；同时自动剥离昵称/绑定频道里的刻意符号隔断与数字插字混淆（如 `-点-简界*·看·橡·-木`、`🔥*抖音1代2刷🔥`），专杀「混淆引流昵称 + 群内只发单个数字蹭曝光」广告号。
* **空白协议号画像风险加权 & 正常群友保护**：自动识别「无真实头像 + 乱码/两段纯字母昵称 + 主页 Bio 空白」批量广告号画像；同时内置**正常群友主页挂博客/GitHub/技术频道链接防误杀红线**，正常群聊绝不因主页带链接被误封。
* **超管私聊转发样本诊断**：超管在私聊里直接把漏网广告转发给机器人，即可当场试跑全载体透视 + AI 评分并将原始 Bot API 结构存入本地 SQLite 便于排查调优（非超管转发一律忽略）。
* **防事后编辑 & 拆分消息聚合**：同时监听 `message` 与 `edited_message`；自动串联同一人近 10 分钟内最多 5 条连续发言送审，抓出拆成多条发的连环软广。
* **灰区复读升权 & 团伙复读 AI 核验**：单次 50～79 分疑似软广 24 小时内反复发送时自动升权击穿阈值并追删副本；60 秒内 ≥ 3 个不同账号发相同内容时触发 AI 核验——群友玩梗复读照常放行，确认为广告后仅封当前发言人并向管理员推送逐人复核卡片，**避免连坐误封**。
* **分级处置降误杀**：高分（默认 ≥ 80）直接删消息并永久封禁清空历史；灰区（65～79，可开关）先删消息并禁言 24 小时，推管理员私聊一键「升级永久封禁」或「解禁并加白名单」。
* **实用防护全家桶（全部 `/config` 一键开关）**：
  * **免费 CAS 全球黑库前置秒杀**（入群瞬间 & 首次发言 0 AI 成本拦截）；
  * **简易 1 点选「🍊 橘子」入群验证**（默认关闭，不与其他验证 Bot 冲突，验证完成或超时自动清消息）；
  * **群内封禁播报 & 定时自毁**（默认 30 分钟自动删除、重启不丢倒计时；`/config` → **📢 封禁播报 ▸** 支持自定义模板与自毁时长）；
  * **一键应急 `/antiraid` 反炸群**（自动静默限制新入群账号）；
  * **木马安装包拦截**（`.apk`/`.exe`/`.msi`/`.bat`/`.scr` 等）；
  * **相册去重 & 分层限流防刷屏**（`media_group_id` 合并算 1 条；普通群友首次仅 60 秒冷静限流）；
  * **洁癖自动清理进退群系统通知**；
  * **群友 `/spam` / `/report` 远程举报**（带防刷限流，管理员私聊一键处决）；
  * **高效缓存**：100% 静态 `SYSTEM_PROMPT` 吃满 Prefix KV Cache + 30 分钟按群隔离的重复广告指纹缓存。

---

## 📖 常用指令

> 机器人启动时会自动按「私聊 / 群成员 / 群管理员」分层注册 Telegram `/` 菜单提示。

| 指令 | 位置 | 作用 |
| --- | --- | --- |
| `/start` | 私聊 | 查看直达链接、**📊 运行状态与战报**、一键配置/更换 AI Key、**一键更换机器人头像/名称/简介**、快捷打开各群面板 |
| `/start` | 群内（管理员） | 唤出AI-智能广告杀手守护状态与管理面板快捷按钮（30 秒后自动清理，支持匿名群管） |
| `/config` | 群内 / 私聊 | 打开可视化按钮面板（含 **📢 封禁播报**、**🛡 豁免/绕过规则**、今日战果与 Token 统计） |
| `/settopic <主题>` | 群内 | 选填群主题降低误杀（`/settopic clear` 恢复默认） |
| `/antiraid [分钟]` | 群内 | 开启应急反炸群（默认 60 分钟；`/antiraid off` 关闭） |
| `/spam` 或 `/report` | 群内回复消息 | 群友举报漏网广告至管理员私聊一键处决（管理员使用直接秒封） |
| `/trust` / `/untrust` | 群内回复消息 | 加入/移出本群永久白名单 |
| `/sban` | 群内回复消息 | 管理员一键秒封、清空历史并写入重复广告黑库 |

## 📄 开源协议

[MIT License](LICENSE)
