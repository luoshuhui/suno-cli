# Suno-CLI 融合 Suno-Downloader 修改说明

## 一、 问题背景与根因分析

在使用 `suno-cli` 下载歌曲时失败，而 Chrome 扩展 `suno-downloader` 可以正常下载，经排查根因如下：

1. **免费/非订阅账号 `BillingInfo` 反序列化错误**：
   * `GET /api/billing/info/` 在免费/非订阅账号下返回的 JSON 中 `"plan": null`。
   * `suno-cli` 原代码中 `BillingInfo.plan` 为非空 `Plan` 结构体，导致调用 `suno credits`、`suno models` 或 `suno download`（默认先请求 `billing_info`）时直接报 `error decoding response body`。
2. **Suno 官方导出下载接口配额限制**：
   * Suno 将 Clip 原本的直链字段 `audio_url` 替换为了 `https://studio-api.prod.suno.com/api/forbidden`，并在 `/api/download/authorize` 中对免费账户限制了下载额度（`current_period_downloads_limit: 0`），返回 `quota_exhausted`。
3. **`suno-downloader` 的工作原理（Mango 协议）**：
   * `suno-downloader` 不走官方导出接口，而是复用网页播放器的流式/渐进式播放解密流程：
     1. 从 `/api/clip/{id}`（或 `/api/feed/?ids={id}`）的 `media_urls` 中选取 `delivery == "progressive"` 的 `m4a-opus` 或 `webm-opus` 音频源。
     2. 请求 `POST /api/mango/rights` 获取包裹后的 `key` 和 `iv`。
     3. 使用 `KEK = SHA-256(jwt 或 glt)`，通过 `AES-256-GCM`（`nonce` 为前 12 字节，`AAD` 为歌曲 `id`）解包得到 16 字节 `keyRaw` 和 16 字节 `ivRaw`。
     4. 下载 CDN 密文并通过 `AES-128-CTR`（128 位大端计数器）在本地解密得到原始音频流。

---

## 二、 核心修改内容

### 1. 修复 `BillingInfo` 反序列化与扩展 `Clip` 媒体源字段 (`src/api/types.rs`)
* 为 `BillingInfo.plan` 增加自定义反序列化函数 `deserialize_plan_or_default`，当 API 返回 `"plan": null` 时自动回退为默认的 `Plan { name: "Free", ... }`。
* 新增 `MediaUrl` 结构体并在 `Clip` 中增加 `media_urls: Vec<MediaUrl>` 字段。

### 2. 新增 Mango 密钥接口与 `--source mango` 默认下载源 (`src/cli.rs`, `src/api/downloads.rs`, `src/api/mod.rs`)
* 在 `DownloadSource` 枚举中新增 `Mango`（`--source mango`），并将其设为默认下载源（`#[default]`）。
* 在 `SunoClient` 中新增 `mango_rights(&self, id: &str)`、`clip_detail(&self, id: &str)` 和 `select_mango_media`。
* 当显式使用 `--source auto` 且官方下载配额耗尽或未解锁时，同样支持自动回退到 `mango` 解密下载。

### 3. 实现本地 AES-GCM / AES-CTR 解密与 `ffmpeg` 自动转码 (`src/download.rs`, `Cargo.toml`)
* 引入 `aes = "0.8"`、`aes-gcm = "0.10"`、`ctr = "0.9"`。
* 实现 `decrypt_mango_audio`：兼容未加密直出流、已登录 JWT 密钥派生以及匿名 `glt` 密钥派生，解密后校验 `ftyp`（M4A）与 EBML（WebM）容器头。
* 实现 `transcode_with_ffmpeg`：
  * `--format m4a`：若源流本身为 `m4a-opus`，直接保存原始解密后的无损容器，不经过重编码。
  * `--format mp3`（默认）：调用本机 `ffmpeg`（`libmp3lame -q:a 2`）转码为 MP3，并保留原有的 ID3v2 歌词（USLT + SYLT）内嵌功能。
  * `--format wav`：调用本机 `ffmpeg`（`pcm_s16le`）转码为 WAV。
  * `--format mp4`（或 `--video`）：自动下载歌曲封面并通过 `ffmpeg` 合成为带静态封面的 MP4 视频。

### 4. `suno list` 表格完整显示多行 UUID (`src/output/table.rs`)
* 将 `suno list` 表格中的 `ID` 栏从仅截取前 8 位改为按 UUID 的 5 段连字符多行折行展示完整 ID，方便直接复制使用且不挤压右侧列宽。

### 5. 更新 Agent Manifest 与 Skills (`src/commands/agent_info.rs`, `assets/SKILL.md`, `tests/agent_info_contract.rs`)
* 更新 `suno agent-info` 中 `download` 命令的 `--source` 默认值为 `"mango"`，可选值为 `["auto", "studio", "library", "mango"]`。
* 更新 `assets/SKILL.md` 并通过 `suno skill install` 同步至本机 Claude Code、Codex CLI、Gemini CLI 及 Agents 技能目录。
