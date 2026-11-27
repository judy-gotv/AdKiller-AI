#!/usr/bin/env bash
set -euo pipefail

# AI-智能广告杀手 (AdKiller AI) One-Line Bootstrap, Interactive Setup Wizard & Terminal CLI
# 支持一行命令直接启动：
#   bash <(curl -fsSL https://raw.githubusercontent.com/judy-gotv/AdKiller-AI/main/setup.sh)
# 安装完成后，在 Linux 终端任意目录输入 `adkiller` 即可随时进入配置与管理。

REPO_URL="${ADKILLER_REPO_URL:-https://github.com/judy-gotv/AdKiller-AI.git}"
INSTALL_DIR="${ADKILLER_DIR:-AdKiller-AI}"

# ---- Parse CLI arguments ----
CLI_MODE=0
INSTALL_CLI_ONLY=0
SUBCMD=""
SUBARG=""
if [[ "${1:-}" == "--cli" ]]; then
  CLI_MODE=1
  shift
  SUBCMD="${1:-}"
  SUBARG="${2:-}"
elif [[ "${1:-}" == "--install-cli" ]]; then
  INSTALL_CLI_ONLY=1
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  SUBCMD="help"
  CLI_MODE=1
elif [[ -n "${1:-}" ]]; then
  SUBCMD="$1"
  SUBARG="${2:-}"
  CLI_MODE=1
fi

# ---- Detect whether we need /dev/tty (for `curl ... | bash`) ----
TTY_FD=""
if [[ -t 0 ]]; then
  TTY_FD="/dev/stdin"
elif [[ -t 1 && -r /dev/tty ]]; then
  TTY_FD="/dev/tty"
fi

# ---- Helper functions ----
trim() {
  local s="${1:-}"
  s="${s//$'\r'/}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

abort_eof() {
  printf '\n❌ 检测到输入中止（EOF），已安全退出：未写入配置、未启动服务。\n' >&2
  exit 1
}

prompt_line() {
  local prompt="$1"
  local __outvar="$2"
  local val=""
  local rc=0
  if [[ "$TTY_FD" == "/dev/tty" ]]; then
    read -r -p "$prompt" val </dev/tty || rc=$?
  else
    read -r -p "$prompt" val || rc=$?
  fi
  if (( rc != 0 )) && [[ -z "$val" ]]; then
    abort_eof
  fi
  printf -v "$__outvar" '%s' "$(trim "$val")"
}

prompt_secret() {
  local prompt="$1"
  local __outvar="$2"
  local val=""
  local rc=0
  if [[ "$TTY_FD" == "/dev/tty" ]]; then
    read -r -s -p "$prompt" val </dev/tty || rc=$?
    printf '\n'
  elif [[ -t 0 ]]; then
    read -r -s -p "$prompt" val || rc=$?
    printf '\n'
  else
    read -r val || rc=$?
  fi
  if (( rc != 0 )) && [[ -z "$val" ]]; then
    abort_eof
  fi
  printf -v "$__outvar" '%s' "$(trim "$val")"
}

verify_adkiller_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || return 1
  [[ -f "${dir}/docker-compose.yml" ]] || return 1
  [[ -f "${dir}/adkiller/__init__.py" ]] || return 1
  [[ -f "${dir}/adkiller/main.py" ]] || return 1
  grep -q 'adkiller' "${dir}/docker-compose.yml" 2>/dev/null || return 1
  grep -q 'AI-智能广告杀手' "${dir}/adkiller/__init__.py" 2>/dev/null || return 1
  return 0
}

normalize_repo_url() {
  local u
  u="$(trim "${1:-}")"
  if [[ "$u" =~ ^git@([^:]+):(.+)$ ]]; then
    u="https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  fi
  u="${u%/}"
  u="${u%.git}"
  printf '%s' "${u,,}"
}

verify_git_remote() {
  local dir="$1"
  [[ -d "${dir}/.git" ]] || return 1
  local actual expected
  actual="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
  [[ -n "$actual" ]] || return 1
  actual="$(normalize_repo_url "$actual")"
  expected="$(normalize_repo_url "$REPO_URL")"
  [[ "$actual" == "$expected" ]]
}

read_existing_env() {
  local key="$1"
  if [[ -f "$ENV_FILE" ]]; then
    local line
    line="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" | tail -n 1 || true)"
    if [[ -n "$line" ]]; then
      local val="${line#*=}"
      val="$(trim "$val")"
      if [[ ( "$val" == \"*\" && "$val" == *\" ) || ( "$val" == \'*\' && "$val" == *\' ) ]]; then
        val="${val:1:${#val}-2}"
      fi
      printf '%s' "$val"
    fi
  fi
}

mask_secret() {
  local s="${1:-}"
  if [[ -z "$s" ]]; then
    printf '未设置'
  elif (( ${#s} <= 10 )); then
    printf '****'
  else
    printf '%s****%s' "${s:0:4}" "${s: -4}"
  fi
}

# ---- Terminal color (clean 3-color palette: cyan + yellow + white) & exact-width box helpers ----
C_RESET=""
C_CYAN=""
C_CYAN_BOLD=""
C_YELLOW=""
C_YELLOW_BOLD=""
C_WHITE=""

init_colors() {
  if [[ ( -t 1 || "${ADKILLER_COLOR:-0}" == "1" ) && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'
    C_CYAN=$'\033[36m'
    C_CYAN_BOLD=$'\033[1;36m'
    C_YELLOW=$'\033[33m'
    C_YELLOW_BOLD=$'\033[1;33m'
    C_WHITE=$'\033[97m'
  fi
}
init_colors

# Locale-independent UTF-8 display width (ASCII/2-byte=1 col, 3/4-byte CJK=2 cols)
display_width() {
  local s="${1:-}"
  (
    export LC_ALL=C
    local -i len=${#s} i=0 w=0 b=0
    while (( i < len )); do
      printf -v b '%d' "'${s:i:1}"
      (( b < 0 )) && b=$(( b + 256 ))
      if (( b < 128 )); then
        w+=1; i+=1
      elif (( b < 224 )); then
        w+=1; i+=2
      elif (( b < 240 )); then
        w+=2; i+=3
      else
        w+=2; i+=4
      fi
    done
    printf '%d' "$w"
  )
}

truncate_width() {
  local s="${1:-}"
  local max_w="${2:-27}"
  local w
  w="$(display_width "$s")"
  if (( w <= max_w )); then
    printf '%s' "$s"
    return
  fi
  (
    export LC_ALL=C
    local -i len=${#s} i=0 cur_w=0 b=0 cw=0 step=1 limit=$(( max_w - 3 ))
    local out=""
    while (( i < len )); do
      printf -v b '%d' "'${s:i:1}"
      (( b < 0 )) && b=$(( b + 256 ))
      if (( b < 128 )); then
        cw=1; step=1
      elif (( b < 224 )); then
        cw=1; step=2
      elif (( b < 240 )); then
        cw=2; step=3
      else
        cw=2; step=4
      fi
      if (( cur_w + cw > limit )); then
        break
      fi
      out+="${s:i:step}"
      cur_w=$(( cur_w + cw ))
      i=$(( i + step ))
    done
    printf '%s...' "$out"
  )
}

BOX_INNER=42
BOX_RULE="──────────────────────────────────────────"

box_top() {
  printf '%s╭%s╮%s\n' "$C_CYAN" "$BOX_RULE" "$C_RESET"
}

box_sep() {
  printf '%s├%s┤%s\n' "$C_CYAN" "$BOX_RULE" "$C_RESET"
}

box_bottom() {
  printf '%s╰%s╯%s\n' "$C_CYAN" "$BOX_RULE" "$C_RESET"
}

# Print a centered line inside the box: box_center <plain_text> <colored_text>
box_center() {
  local plain="$1"
  local colored="$2"
  local w pad_l pad_r
  w="$(display_width "$plain")"
  pad_l=$(( (BOX_INNER - w) / 2 ))
  (( pad_l < 0 )) && pad_l=0
  pad_r=$(( BOX_INNER - w - pad_l ))
  (( pad_r < 0 )) && pad_r=0
  printf '%s│%s%*s%s%*s%s│%s\n' \
    "$C_CYAN" "$C_RESET" "$pad_l" "" "$colored" "$pad_r" "" "$C_CYAN" "$C_RESET"
}

# Print a key-value row inside the box: box_kv <4-CJK-label> <plain_value> <value_color>
box_kv() {
  local label="$1"
  local val="$2"
  local vcolor="$3"
  local clipped w pad_r
  clipped="$(truncate_width "$val" 27)"
  # Layout: "  " (2) + label (8) + "   " (3) + clipped (<=27) + pad_r -> total 42
  w=$(( 2 + $(display_width "$label") + 3 + $(display_width "$clipped") ))
  pad_r=$(( BOX_INNER - w ))
  (( pad_r < 0 )) && pad_r=0
  printf '%s│%s  %s%s%s   %s%s%s%*s%s│%s\n' \
    "$C_CYAN" "$C_RESET" \
    "$C_CYAN" "$label" "$C_RESET" \
    "$vcolor" "$clipped" "$C_RESET" \
    "$pad_r" "" \
    "$C_CYAN" "$C_RESET"
}

# Print a symmetric 2-column menu row (every item is "[N] 四字名称" = 12 cols)
# Layout: 4 + 12 + 10 + 12 + 4 = 42 cols exact!
box_menu_row() {
  local k1="$1" t1="$2"
  local k2="$3" t2="$4"
  printf '%s│%s    %s[%s]%s %s%s%s          %s[%s]%s %s%s%s    %s│%s\n' \
    "$C_CYAN" "$C_RESET" \
    "$C_CYAN_BOLD" "$k1" "$C_RESET" "$C_WHITE" "$t1" "$C_RESET" \
    "$C_CYAN_BOLD" "$k2" "$C_RESET" "$C_WHITE" "$t2" "$C_RESET" \
    "$C_CYAN" "$C_RESET"
}

is_valid_token() {
  [[ "$1" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{20,}$ ]]
}

is_valid_owner_ids() {
  local cleaned="${1// /}"
  [[ "$cleaned" =~ ^[0-9]+(,[0-9]+)*$ ]]
}

# Require HTTPS for all remote hosts; allow HTTP ONLY on explicit local loopback hosts.
# Also reject userinfo (@), query parameters (?), and fragments (#).
is_valid_base_url() {
  local url="$1"
  [[ -z "$url" || ${#url} -gt 300 || "$url" =~ [[:space:]?#] ]] && return 1
  if [[ "$url" =~ ^[Hh][Tt][Tt][Pp][Ss]://([^/@[:space:]?#]+)(/[^[:space:]?#]*)?$ ]]; then
    return 0
  fi
  if [[ "$url" =~ ^[Hh][Tt][Tt][Pp]://(localhost|127\.0\.0\.1|\[::1\]|host\.docker\.internal)(:[0-9]{1,5})?(/[^[:space:]?#]*)?$ ]]; then
    return 0
  fi
  return 1
}

# Normalize URL origin (scheme://host:port) so switching hosts never reuses an old API key
url_origin() {
  local url="${1:-}"
  local scheme="" authority="" host="" port=""
  if [[ "$url" =~ ^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+) ]]; then
    scheme="${BASH_REMATCH[1],,}"
    authority="${BASH_REMATCH[2],,}"
  else
    printf ''
    return
  fi
  authority="${authority##*@}"
  if [[ "$authority" =~ ^(\[::1\]):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  elif [[ "$authority" == "[::1]" ]]; then
    host="[::1]"
  elif [[ "$authority" == *:* ]]; then
    host="${authority%:*}"
    port="${authority##*:}"
  else
    host="$authority"
  fi
  if [[ -z "$port" ]]; then
    if [[ "$scheme" == "https" ]]; then
      port="443"
    elif [[ "$scheme" == "http" ]]; then
      port="80"
    fi
  fi
  printf '%s://%s:%s' "$scheme" "$host" "$port"
}

# Display ONLY scheme://host[:port] — strips userinfo, path, query, and fragment!
sanitize_url() {
  local url="${1:-}"
  local origin
  origin="$(url_origin "$url")"
  if [[ -z "$origin" ]]; then
    printf '(格式无效的地址)'
    return
  fi
  origin="${origin%:443}"
  if [[ "$origin" == http://* ]]; then
    origin="${origin%:80}"
  fi
  printf '%s' "$origin"
}

resolve_script_dir() {
  local src="$1"
  while [[ -L "$src" ]]; do
    local dir link
    dir="$(cd -P "$(dirname "$src")" && pwd)"
    link="$(readlink "$src")"
    if [[ "$link" == /* ]]; then
      src="$link"
    else
      src="${dir}/${link}"
    fi
  done
  cd -P "$(dirname "$src")" && pwd
}

COMPOSE_CMD=()
detect_compose_cmd() {
  COMPOSE_CMD=()
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  fi
}

require_compose_or_exit() {
  detect_compose_cmd
  if (( ${#COMPOSE_CMD[@]} == 0 )); then
    printf '❌ 当前系统未检测到 docker compose，请先安装 Docker 后再执行此操作。\n' >&2
    exit 1
  fi
}

box_help_row() {
  local cmd_txt="$1"
  local desc="$2"
  local w pad_mid pad_r
  # "  " (2) + cmd (padded to 20) + "  " (2) + desc (8) + pad_r -> 42
  w="$(display_width "$cmd_txt")"
  pad_mid=$(( 20 - w ))
  (( pad_mid < 1 )) && pad_mid=1
  pad_r=$(( BOX_INNER - 2 - w - pad_mid - 2 - $(display_width "$desc") ))
  (( pad_r < 0 )) && pad_r=0
  printf '%s│%s  %s%s%s%*s  %s%s%s%*s%s│%s\n' \
    "$C_CYAN" "$C_RESET" \
    "$C_CYAN_BOLD" "$cmd_txt" "$C_RESET" \
    "$pad_mid" "" \
    "$C_WHITE" "$desc" "$C_RESET" \
    "$pad_r" "" \
    "$C_CYAN" "$C_RESET"
}

print_cli_help() {
  printf '\n'
  box_top
  box_center "AI-智能广告杀手  命令" "${C_YELLOW_BOLD}AI-智能广告杀手  命令${C_RESET}"
  box_sep
  box_help_row "adkiller"         "打开菜单"
  box_help_row "adkiller config"  "修改配置"
  box_help_row "adkiller status"  "查看状态"
  box_help_row "adkiller brand"   "更换头像"
  box_help_row "adkiller update"  "更新版本"
  box_help_row "adkiller restart" "启动重启"
  box_help_row "adkiller logs"    "实时日志"
  box_help_row "adkiller stop"    "停止服务"
  box_bottom
}

# ---- Safe Telegram Bot API helpers (pass URL via stdin to curl -K - so token NEVER appears in argv!) ----
BOT_DEFAULT_NAME="AI-智能广告杀手"
BOT_DEFAULT_SHORT_DESC="🛡 AI-智能广告杀手 · 开源 AI 群管反广告守卫"
BOT_DEFAULT_DESC=$'🛡 AI-智能广告杀手 — 开源自托管 AI 反广告守卫。\n拉我进群设为管理员（勾选删消息、封禁用户），群内发 /config 即可一键开关全部防护。'
LAST_BOT_USERNAME=""

tg_token_fingerprint() {
  local tok="${1:-}"
  [[ -n "$tok" ]] || { printf ''; return; }
  printf '%s:%s' "${tok%%:*}" "${tok: -4}"
}

read_cached_bot_username() {
  local tok="${1:-}"
  local meta="${WORK_DIR}/data/.bot_meta"
  [[ -n "$tok" && -f "$meta" ]] || return 1
  local fp expected_fp uname
  expected_fp="$(tg_token_fingerprint "$tok")"
  IFS='=' read -r fp uname < "$meta" || return 1
  if [[ "$fp" == "$expected_fp" && "$uname" =~ ^[A-Za-z0-9_]+$ ]]; then
    printf '%s' "$uname"
    return 0
  fi
  return 1
}

save_cached_bot_username() {
  local tok="${1:-}"
  local uname="${2:-}"
  [[ -n "$tok" && "$uname" =~ ^[A-Za-z0-9_]+$ ]] || return 0
  local data_dir="${WORK_DIR}/data"
  mkdir -p "$data_dir" 2>/dev/null || return 0
  local meta="${data_dir}/.bot_meta"
  local fp
  fp="$(tg_token_fingerprint "$tok")"
  (
    umask 077
    printf '%s=%s\n' "$fp" "$uname" > "${meta}.tmp.$$"
    chmod 600 "${meta}.tmp.$$"
  ) && mv -f "${meta}.tmp.$$" "$meta" 2>/dev/null || true
}

tg_fetch_bot_username() {
  local token="${1:-}"
  [[ "${ADKILLER_SKIP_TG_API:-0}" == "1" ]] && return 1
  [[ -n "$token" ]] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  local resp=""
  resp="$(printf 'url = "https://api.telegram.org/bot%s/getMe"\n' "$token" \
    | curl -fsS --max-time 6 -K - 2>/dev/null || true)"
  if [[ "$resp" =~ \"ok\"[[:space:]]*:[[:space:]]*true ]] && [[ "$resp" =~ \"username\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_]+)\" ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

tg_api_ok() {
  local resp="${1:-}"
  [[ "$resp" =~ \"ok\"[[:space:]]*:[[:space:]]*true ]]
}

apply_bot_branding_cli() {
  local token="${1:-}"
  if [[ "${ADKILLER_SKIP_TG_API:-0}" == "1" ]]; then
    printf '%s已跳过外部 Telegram API 调用（测试模式）。%s\n' "$C_YELLOW" "$C_RESET"
    return 0
  fi
  if [[ -z "$token" ]]; then
    printf '%s未配置 Bot Token，无法设置机器人头像与简介。%s\n' "$C_YELLOW" "$C_RESET"
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    printf '%s未检测到 curl，已跳过自动设置头像与简介（启动后可在机器人私聊 /start 一键更换）。%s\n' "$C_YELLOW" "$C_RESET"
    return 1
  fi

  printf '\n%s正在将机器人资料更新为「AI-智能广告杀手」...%s\n' "$C_CYAN" "$C_RESET"
  local resp=""

  resp="$(printf 'url = "https://api.telegram.org/bot%s/setMyName"\n' "$token" \
    | curl -fsS --max-time 10 -K - --data-urlencode "name=${BOT_DEFAULT_NAME}" 2>/dev/null || true)"
  if tg_api_ok "$resp"; then
    printf '  %s名称%s   %s已更新 (%s)%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$BOT_DEFAULT_NAME" "$C_RESET"
  else
    printf '  %s名称%s   %s更新失败（可稍后在私聊 /start 重试）%s\n' "$C_CYAN" "$C_RESET" "$C_YELLOW" "$C_RESET"
  fi

  resp="$(printf 'url = "https://api.telegram.org/bot%s/setMyShortDescription"\n' "$token" \
    | curl -fsS --max-time 10 -K - --data-urlencode "short_description=${BOT_DEFAULT_SHORT_DESC}" 2>/dev/null || true)"
  if tg_api_ok "$resp"; then
    printf '  %s简介%s   %s已更新%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$C_RESET"
  else
    printf '  %s简介%s   %s更新失败（可稍后在私聊 /start 重试）%s\n' "$C_CYAN" "$C_RESET" "$C_YELLOW" "$C_RESET"
  fi

  resp="$(printf 'url = "https://api.telegram.org/bot%s/setMyDescription"\n' "$token" \
    | curl -fsS --max-time 10 -K - --data-urlencode "description=${BOT_DEFAULT_DESC}" 2>/dev/null || true)"
  if tg_api_ok "$resp"; then
    printf '  %s说明%s   %s已更新%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$C_RESET"
  else
    printf '  %s说明%s   %s更新失败（可稍后在私聊 /start 重试）%s\n' "$C_CYAN" "$C_RESET" "$C_YELLOW" "$C_RESET"
  fi

  local avatar_file="${WORK_DIR}/assets/avatar.jpg"
  if [[ -f "$avatar_file" ]]; then
    resp="$(printf 'url = "https://api.telegram.org/bot%s/setMyProfilePhoto"\n' "$token" \
      | curl -fsS --max-time 15 -K - \
        -F 'photo={"type":"static","photo":"attach://avatar"}' \
        -F "avatar=@${avatar_file};type=image/jpeg" 2>/dev/null || true)"
    if tg_api_ok "$resp"; then
      printf '  %s头像%s   %s已更换为AI-智能广告杀手官方图标%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$C_RESET"
    else
      printf '  %s头像%s   %s更换失败（可稍后在私聊 /start 重试）%s\n' "$C_CYAN" "$C_RESET" "$C_YELLOW" "$C_RESET"
    fi
  else
    printf '  %s头像%s   %s未找到 assets/avatar.jpg%s\n' "$C_CYAN" "$C_RESET" "$C_YELLOW" "$C_RESET"
  fi
}

CLI_MARKER='# AdKiller-AI CLI launcher'
INSTALLED_BIN_PATH=""

install_cli_shortcut() {
  if [[ "${ADKILLER_NO_BIN:-0}" == "1" ]]; then
    return 0
  fi
  if ! verify_adkiller_dir "$WORK_DIR"; then
    return 1
  fi

  local target_dir=""
  if [[ -n "${ADKILLER_BIN_DIR:-}" ]]; then
    target_dir="$ADKILLER_BIN_DIR"
    mkdir -p "$target_dir" 2>/dev/null || {
      printf '⚠️  无法创建自定义命令目录 %s，已跳过安装 adkiller 快捷命令。\n' "$target_dir" >&2
      return 0
    }
  elif [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
    target_dir="/usr/local/bin"
  elif [[ -n "${HOME:-}" ]]; then
    target_dir="${HOME}/.local/bin"
    mkdir -p "$target_dir" 2>/dev/null || {
      printf '⚠️  无法创建 %s，已跳过安装 adkiller 快捷命令。\n' "$target_dir" >&2
      return 0
    }
  else
    return 0
  fi

  local target_bin="${target_dir}/adkiller"
  if [[ -e "$target_bin" || -L "$target_bin" ]]; then
    if [[ ! -f "$target_bin" ]] || ! grep -qF "$CLI_MARKER" "$target_bin" 2>/dev/null; then
      printf '⚠️  检测到 %s 已存在且非AI-智能广告杀手快捷命令，为避免覆盖已跳过。\n' "$target_bin" >&2
      return 0
    fi
  fi

  local escaped_dir
  escaped_dir="'${WORK_DIR//\'/\'\\\'\'}'"
  local tmp_bin="${target_bin}.tmp.$$"
  {
    printf '#!/usr/bin/env bash\n'
    printf '%s (auto-generated by setup.sh)\n' "$CLI_MARKER"
    printf 'set -euo pipefail\n'
    printf 'ADKILLER_HOME=%s\n' "$escaped_dir"
    printf 'if [[ ! -f "${ADKILLER_HOME}/setup.sh" ]]; then\n'
    printf '  printf '\''❌ 找不到 AI-智能广告杀手 安装目录：%%s\\n'\'' "$ADKILLER_HOME" >&2\n'
    printf '  printf '\''   请重新运行安装脚本以修复快捷命令。\\n'\'' >&2\n'
    printf '  exit 1\n'
    printf 'fi\n'
    printf 'exec bash "${ADKILLER_HOME}/setup.sh" --cli "$@"\n'
  } > "$tmp_bin"
  chmod 755 "$tmp_bin"
  mv -f "$tmp_bin" "$target_bin"
  INSTALLED_BIN_PATH="$target_bin"

  printf '⚡ 终端快捷命令已就绪：%s\n' "$target_bin"
  if [[ ":$PATH:" == *":${target_dir}:"* ]]; then
    printf '   以后在终端任意目录直接输入 adkiller 即可进入配置与管理！\n'
  else
    printf '   💡 当前 PATH 尚未包含 %s，执行下面任意一条即可全局直接输入 adkiller：\n' "$target_dir"
    printf '      • 系统全局命令：sudo ln -sf %q /usr/local/bin/adkiller\n' "$target_bin"
    printf '      • 或加入当前用户 PATH：echo '\''export PATH="%s:$PATH"'\'' >> ~/.bashrc && source ~/.bashrc\n' "$target_dir"
  fi
}

uninstall_cli_shortcut() {
  local removed=0
  local candidates=()
  [[ -n "${ADKILLER_BIN_DIR:-}" ]] && candidates+=("${ADKILLER_BIN_DIR}/adkiller")
  candidates+=("/usr/local/bin/adkiller")
  [[ -n "${HOME:-}" ]] && candidates+=("${HOME}/.local/bin/adkiller")

  local p
  for p in "${candidates[@]}"; do
    if [[ -f "$p" ]] && grep -qF "$CLI_MARKER" "$p" 2>/dev/null; then
      if rm -f "$p" 2>/dev/null; then
        printf '✅ 已卸载终端快捷命令：%s\n' "$p"
        removed=1
      else
        printf '⚠️  权限不足，无法删除 %s，请尝试：sudo rm -f %q\n' "$p" "$p" >&2
      fi
    fi
  done
  if (( removed == 0 )); then
    printf 'ℹ️  未检测到已安装的 adkiller 终端快捷命令。\n'
  fi
}

is_container_running() {
  detect_compose_cmd
  if (( ${#COMPOSE_CMD[@]} == 0 )); then
    return 1
  fi
  local running_ids=""
  if running_ids="$(cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" ps --status running -q 2>/dev/null)" && [[ -n "$running_ids" ]]; then
    return 0
  fi
  return 1
}

# ---- Read-only live stats helper (reads BOTH .env and SQLite data/adkiller.db!) ----
# Uses host python3 stdlib directly (~25ms) or falls back to running inside the container.
run_cli_stats() {
  local mode="${1:-summary}"
  local script="${WORK_DIR}/adkiller/cli_stats.py"
  [[ -f "$script" ]] || return 1
  local py_bin="${ADKILLER_PYTHON:-}"
  if [[ -z "$py_bin" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      py_bin="python3"
    elif command -v python >/dev/null 2>&1; then
      py_bin="python"
    fi
  fi
  if [[ -n "$py_bin" ]]; then
    "$py_bin" "$script" "$mode" "$WORK_DIR" 2>/dev/null && return 0
  fi
  detect_compose_cmd
  if (( ${#COMPOSE_CMD[@]} > 0 )) && is_container_running; then
    (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" exec -T adkiller python -m adkiller.cli_stats "$mode" /app 2>/dev/null) && return 0
  fi
  return 1
}

STAT_AI_CONFIGURED=""
STAT_AI_MODEL=""
STAT_AI_SOURCE=""
STAT_GROUPS_TOTAL="0"
STAT_GROUPS_ENABLED="0"
STAT_TODAY_BANS="0"
STAT_TOTAL_BANS="0"
STAT_SUSPECT_TOTAL="0"

load_runtime_summary() {
  STAT_AI_CONFIGURED=""
  STAT_AI_MODEL=""
  STAT_AI_SOURCE=""
  STAT_GROUPS_TOTAL="0"
  STAT_GROUPS_ENABLED="0"
  STAT_TODAY_BANS="0"
  STAT_TOTAL_BANS="0"
  STAT_SUSPECT_TOTAL="0"

  local raw=""
  raw="$(run_cli_stats summary || true)"
  [[ -n "$raw" ]] || return 0
  local k v
  while IFS='=' read -r k v; do
    v="${v//$'\r'/}"
    case "$k" in
      AI_CONFIGURED) STAT_AI_CONFIGURED="$v" ;;
      AI_MODEL)      STAT_AI_MODEL="$v" ;;
      AI_SOURCE)     STAT_AI_SOURCE="$v" ;;
      GROUPS_TOTAL)  STAT_GROUPS_TOTAL="$v" ;;
      GROUPS_ENABLED) STAT_GROUPS_ENABLED="$v" ;;
      TODAY_BANS)    STAT_TODAY_BANS="$v" ;;
      TOTAL_BANS)    STAT_TOTAL_BANS="$v" ;;
      SUSPECT_TOTAL) STAT_SUSPECT_TOTAL="$v" ;;
    esac
  done <<< "$raw"
}

run_status_submenu() {
  if ! run_cli_stats overview; then
    show_status_summary
    printf '%s提示：未找到可读的统计数据库或 Python 环境。%s\n' "$C_YELLOW" "$C_RESET"
    return 0
  fi

  while true; do
    printf '\n'
    box_top
    box_center "状态详情  子菜单" "${C_YELLOW_BOLD}状态详情  子菜单${C_RESET}"
    box_sep
    box_menu_row "1" "广告击杀" "2" "疑似排查"
    box_menu_row "3" "模型汇报" "0" "返回上级"
    box_bottom
    printf '\n'
    local sub=""
    prompt_line "  ${C_YELLOW_BOLD}请选择${C_RESET} ${C_CYAN}[0-3，回车返回]${C_RESET}: " sub
    case "${sub:-0}" in
      1) run_cli_stats kills || true ;;
      2) run_cli_stats suspects || true ;;
      3) run_cli_stats ai || true ;;
      0) return 0 ;;
      *) printf '  %s无效选项：%s%s\n' "$C_YELLOW" "$sub" "$C_RESET" ;;
    esac
  done
}

render_status_rows() {
  local tok own aikey aimodel
  tok="$(read_existing_env TELEGRAM_BOT_TOKEN)"
  own="$(read_existing_env OWNER_IDS)"
  aikey="$(read_existing_env AI_API_KEY)"
  aimodel="$(read_existing_env AI_MODEL)"

  local state_txt state_col
  detect_compose_cmd
  if (( ${#COMPOSE_CMD[@]} == 0 )); then
    state_txt="未装Docker"
    state_col="$C_YELLOW"
  elif ! (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" ps -q >/dev/null 2>&1); then
    state_txt="Docker未启"
    state_col="$C_YELLOW"
  elif is_container_running; then
    state_txt="运行中"
    state_col="$C_WHITE"
  else
    state_txt="已停止"
    state_col="$C_YELLOW"
  fi

  local tok_txt tok_col
  if [[ -n "$tok" ]]; then
    tok_txt="$(mask_secret "$tok")"
    tok_col="$C_WHITE"
  else
    tok_txt="未设置"
    tok_col="$C_YELLOW"
  fi

  local own_txt own_col
  if [[ -n "$own" ]]; then
    own_txt="$own"
    own_col="$C_WHITE"
  else
    own_txt="未设置"
    own_col="$C_YELLOW"
  fi

  local ai_txt ai_col
  load_runtime_summary
  if [[ "$STAT_AI_CONFIGURED" == "1" ]]; then
    if [[ "$STAT_AI_SOURCE" == "telegram" ]]; then
      ai_txt="${STAT_AI_MODEL:-已配置} (私聊配)"
    else
      ai_txt="${STAT_AI_MODEL:-已配置}"
    fi
    ai_col="$C_WHITE"
  elif [[ "$STAT_AI_CONFIGURED" == "0" ]]; then
    ai_txt="未配置"
    ai_col="$C_YELLOW"
  elif [[ -n "$aikey" ]]; then
    ai_txt="${aimodel:-已配置}"
    ai_col="$C_WHITE"
  else
    ai_txt="未配置"
    ai_col="$C_YELLOW"
  fi

  local grp_txt grp_col
  if (( STAT_GROUPS_TOTAL > 0 )); then
    grp_txt="${STAT_GROUPS_ENABLED}/${STAT_GROUPS_TOTAL} 群 (今杀 ${STAT_TODAY_BANS})"
    grp_col="$C_WHITE"
  else
    grp_txt="0 个群"
    grp_col="$C_YELLOW"
  fi

  LAST_BOT_USERNAME=""
  local link_txt link_col
  if [[ -n "$tok" ]]; then
    if LAST_BOT_USERNAME="$(read_cached_bot_username "$tok" || true)" && [[ -n "$LAST_BOT_USERNAME" ]]; then
      :
    elif LAST_BOT_USERNAME="$(tg_fetch_bot_username "$tok" || true)" && [[ -n "$LAST_BOT_USERNAME" ]]; then
      save_cached_bot_username "$tok" "$LAST_BOT_USERNAME"
    fi
  fi
  if [[ -n "$LAST_BOT_USERNAME" ]]; then
    link_txt="t.me/${LAST_BOT_USERNAME}"
    link_col="$C_WHITE"
  else
    link_txt="未获取"
    link_col="$C_YELLOW"
  fi

  box_kv "运行状态" "$state_txt" "$state_col"
  box_kv "防护群组" "$grp_txt" "$grp_col"
  box_kv "安装目录" "$WORK_DIR" "$C_WHITE"
  box_kv "机器链接" "$link_txt" "$link_col"
  box_kv "机器令牌" "$tok_txt" "$tok_col"
  box_kv "超管编号" "$own_txt" "$own_col"
  box_kv "模型引擎" "$ai_txt" "$ai_col"
}

show_status_summary() {
  printf '\n'
  box_top
  box_center "AI-智能广告杀手" "${C_YELLOW_BOLD}AI-智能广告杀手${C_RESET}"
  box_sep
  render_status_rows
  box_bottom
  if [[ -n "$LAST_BOT_USERNAME" ]]; then
    printf '  %s直达链接%s   %shttps://t.me/%s%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$LAST_BOT_USERNAME" "$C_RESET"
  fi
}

run_cli_subcommand() {
  local cmd="$1"
  case "$cmd" in
    help|-h|--help)
      print_cli_help
      exit 0
      ;;
    status)
      case "${SUBARG:-}" in
        kills|suspects|ai|overview)
          run_cli_stats "$SUBARG" || show_status_summary
          ;;
        *)
          show_status_summary
          if [[ -t 0 && -t 1 ]]; then
            run_status_submenu
          else
            run_cli_stats overview || true
          fi
          ;;
      esac
      exit 0
      ;;
    logs)
      require_compose_or_exit
      printf '%s正在查看AI-智能广告杀手实时日志（按 Ctrl+C 退出）...%s\n' "$C_CYAN" "$C_RESET"
      (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" logs -f --tail=100) || true
      exit 0
      ;;
    start)
      require_compose_or_exit
      (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" up -d --build)
      printf '%sAI-智能广告杀手已启动！%s\n' "$C_CYAN_BOLD" "$C_RESET"
      exit 0
      ;;
    restart)
      require_compose_or_exit
      if is_container_running; then
        (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" up -d --force-recreate adkiller)
        printf '%sAI-智能广告杀手已重建并重启（已重新加载 .env 配置）！%s\n' "$C_CYAN_BOLD" "$C_RESET"
      else
        (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" up -d --build)
        printf '%sAI-智能广告杀手已启动！%s\n' "$C_CYAN_BOLD" "$C_RESET"
      fi
      exit 0
      ;;
    stop)
      require_compose_or_exit
      (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" down)
      printf '%sAI-智能广告杀手已停止。%s\n' "$C_YELLOW" "$C_RESET"
      exit 0
      ;;
    update)
      if ! command -v git >/dev/null 2>&1; then
        printf '❌ 未检测到 git，无法在线更新。\n' >&2
        exit 1
      fi
      if ! verify_git_remote "$WORK_DIR"; then
        printf '❌ 目录 %s 缺少有效的 Git 远端元数据（例如早期通过压缩包部署，或远端与官方仓库不匹配），无法执行 git pull。\n' "$WORK_DIR" >&2
        printf '   💡 若为旧版/压缩包安装迁移至最新公开版，请按 README「旧版/压缩包迁移」保留 .env 与 data/ 后重新克隆并执行 bash setup.sh --install-cli。\n' >&2
        exit 1
      fi
      printf '%s正在拉取 AI-智能广告杀手 最新代码...%s\n' "$C_CYAN" "$C_RESET"
      if ! git -C "$WORK_DIR" pull --ff-only; then
        printf '❌ 拉取更新失败（若为公开发布前的旧克隆，因历史已重置，git pull --ff-only 会拒绝快进）。\n' >&2
        printf '   💡 请备份当前目录的 .env 与 data/ 后重新克隆最新公开仓库，或参阅 README「旧版/压缩包迁移」说明。\n' >&2
        exit 1
      fi
      if ! verify_adkiller_dir "$WORK_DIR"; then
        printf '❌ 更新后未通过项目身份校验，已安全中止。\n' >&2
        exit 1
      fi
      install_cli_shortcut
      require_compose_or_exit
      (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" up -d --build)
      printf '%sAI-智能广告杀手已更新到最新版本并重新启动！%s\n' "$C_CYAN_BOLD" "$C_RESET"
      exit 0
      ;;
    uninstall-cmd)
      uninstall_cli_shortcut
      exit 0
      ;;
    brand)
      local cur_tok
      cur_tok="$(read_existing_env TELEGRAM_BOT_TOKEN)"
      apply_bot_branding_cli "$cur_tok"
      exit 0
      ;;
    config)
      return 0
      ;;
    *)
      printf '❌ 未知子命令：%s\n\n' "$cmd" >&2
      print_cli_help >&2
      exit 2
      ;;
  esac
}

run_cli_menu() {
  while true; do
    printf '\n'
    box_top
    box_center "AI-智能广告杀手" "${C_YELLOW_BOLD}AI-智能广告杀手${C_RESET}"
    box_sep
    render_status_rows
    box_sep
    box_menu_row "1" "修改配置" "2" "运行状态"
    box_menu_row "3" "更新版本" "4" "启动重启"
    box_menu_row "5" "实时日志" "6" "停止服务"
    box_menu_row "7" "更换头像" "0" "退出菜单"
    box_bottom
    if [[ -n "$LAST_BOT_USERNAME" ]]; then
      printf '  %s直达链接%s   %shttps://t.me/%s%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$LAST_BOT_USERNAME" "$C_RESET"
    fi
    printf '\n'
    local choice=""
    prompt_line "  ${C_YELLOW_BOLD}请选择${C_RESET} ${C_CYAN}[0-7，回车默认 1]${C_RESET}: " choice
    case "${choice:-1}" in
      1)
        printf '\n'
        return 0
        ;;
      2) run_status_submenu ;;
      3) run_cli_subcommand "update" ;;
      4) run_cli_subcommand "restart" ;;
      5) run_cli_subcommand "logs" ;;
      6) run_cli_subcommand "stop" ;;
      7) run_cli_subcommand "brand" ;;
      0)
        printf '%s已退出。%s\n' "$C_WHITE" "$C_RESET"
        exit 0
        ;;
      *)
        printf '❌ 无效选项：%s\n' "$choice" >&2
        exit 1
        ;;
    esac
  done
}

if [[ "$SUBCMD" == "help" || "$SUBCMD" == "-h" || "$SUBCMD" == "--help" ]]; then
  print_cli_help
  exit 0
fi

# ---- Step 0: Distinguish explicit local run vs remote one-line bootstrap ----
SRC_PATH="${BASH_SOURCE[0]:-}"
IS_LOCAL_FILE=0
SCRIPT_DIR=""
if [[ -n "$SRC_PATH" && ! "$SRC_PATH" =~ ^/(dev|proc)/ && -f "$SRC_PATH" && ! -p "$SRC_PATH" ]]; then
  IS_LOCAL_FILE=1
  SCRIPT_DIR="$(resolve_script_dir "$SRC_PATH")"
fi

if (( IS_LOCAL_FILE == 1 )) && verify_adkiller_dir "$SCRIPT_DIR"; then
  WORK_DIR="$SCRIPT_DIR"
else
  if (( CLI_MODE == 1 || INSTALL_CLI_ONLY == 1 )); then
    printf '❌ 未找到有效的 AI-智能广告杀手 项目目录，请先在项目目录内运行 bash setup.sh。\n' >&2
    exit 1
  fi
  printf '\n'
  box_top
  box_center "AI-智能广告杀手  一键安装" "${C_YELLOW_BOLD}AI-智能广告杀手  一键安装${C_RESET}"
  box_bottom
  printf '%s  按提示输入即可一键部署（密钥输入已隐藏回显）%s\n\n' "$C_WHITE" "$C_RESET"
  # Remote bootstrap mode (or script invoked from outside a AI-智能广告杀手 repo):
  # ALWAYS verify Git origin remote + project markers before touching any existing directory!
  if ! command -v git >/dev/null 2>&1; then
    printf '❌ 未检测到 git，请先安装 git（例如 apt install -y git）后再运行。\n' >&2
    exit 1
  fi

  CUR_DIR="$(pwd)"
  if verify_adkiller_dir "$CUR_DIR"; then
    if ! verify_git_remote "$CUR_DIR"; then
      printf '❌ 当前目录包含 AI-智能广告杀手 项目文件，但其 Git 远端与官方仓库不匹配。\n' >&2
      printf '   • 若要配置此本地副本，请直接运行：bash ./setup.sh\n' >&2
      printf '   • 若要全新安装，请切换到其他空目录或设置 ADKILLER_DIR=<目录名> 后重试。\n' >&2
      exit 1
    fi
    printf '📦 检测到当前目录为已核验的 AI-智能广告杀手 仓库，正在同步最新代码...\n'
    if ! git -C "$CUR_DIR" pull --ff-only; then
      printf '❌ 当前目录拉取更新失败，为安全起见已中止。请手动检查 git 状态后重试。\n' >&2
      exit 1
    fi
    WORK_DIR="$CUR_DIR"
  elif [[ -e "$INSTALL_DIR" ]]; then
    if ! verify_git_remote "$INSTALL_DIR" || ! verify_adkiller_dir "$INSTALL_DIR"; then
      printf '❌ 目录 ./%s 已存在，但无法确认它是有效的 AI-智能广告杀手 仓库（远端地址或项目文件不匹配）。\n' "$INSTALL_DIR" >&2
      printf '   为防止误写其他项目的 .env 或执行错误 Compose 配置，已安全退出。\n' >&2
      printf '   请改用其他目录重新运行，例如：ADKILLER_DIR=adkiller-bot bash ...\n' >&2
      exit 1
    fi
    printf '📦 检测到已核验的 AI-智能广告杀手 目录 ./%s，正在同步最新代码...\n' "$INSTALL_DIR"
    if ! git -C "$INSTALL_DIR" pull --ff-only; then
      printf '❌ 目录 ./%s 拉取更新失败，为安全起见已中止。请手动检查该目录的 git 状态后重试。\n' "$INSTALL_DIR" >&2
      exit 1
    fi
    WORK_DIR="$(cd "$INSTALL_DIR" && pwd)"
  else
    printf '📦 正在克隆 AI-智能广告杀手 到 ./%s ...\n' "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
    if ! verify_adkiller_dir "$INSTALL_DIR"; then
      printf '❌ 克隆后的目录 ./%s 未通过 AI-智能广告杀手 项目文件校验，已安全退出。\n' "$INSTALL_DIR" >&2
      exit 1
    fi
    WORK_DIR="$(cd "$INSTALL_DIR" && pwd)"
  fi
  printf '📁 目标目录（已核验仓库）：%s\n\n' "$WORK_DIR"
fi

ENV_FILE="${WORK_DIR}/.env"

if (( INSTALL_CLI_ONLY == 1 )); then
  install_cli_shortcut
  exit 0
fi

if (( CLI_MODE == 1 )); then
  if [[ -n "$SUBCMD" ]]; then
    run_cli_subcommand "$SUBCMD"
  elif [[ -f "$ENV_FILE" ]]; then
    run_cli_menu
  fi
fi

if (( IS_LOCAL_FILE == 1 )); then
  printf '\n'
  box_top
  box_center "AI-智能广告杀手  配置向导" "${C_YELLOW_BOLD}AI-智能广告杀手  配置向导${C_RESET}"
  box_bottom
  printf '%s  目录：%s（密钥输入已隐藏回显）%s\n\n' "$C_WHITE" "$WORK_DIR" "$C_RESET"
fi

# Load existing values if re-running setup.sh
OLD_TOKEN="$(read_existing_env TELEGRAM_BOT_TOKEN)"
OLD_OWNERS="$(read_existing_env OWNER_IDS)"
OLD_AI_KEY="$(read_existing_env AI_API_KEY)"
OLD_AI_URL="$(read_existing_env AI_BASE_URL)"
OLD_AI_MODEL="$(read_existing_env AI_MODEL)"

# Re-validate any existing AI_BASE_URL from a prior .env (print ONLY sanitized host!)
if [[ -n "$OLD_AI_URL" ]] && ! is_valid_base_url "$OLD_AI_URL"; then
  printf '⚠️  检测到原有 .env 中的 AI 接口地址（%s）不合规（远程仅允许无查询参数的 https://）。\n' "$(sanitize_url "$OLD_AI_URL")" >&2
  printf '   已自动清空旧 AI_API_KEY 并将接口重置为默认 https://api.deepseek.com/v1。\n\n' >&2
  OLD_AI_URL="https://api.deepseek.com/v1"
  OLD_AI_KEY=""
fi
OLD_AI_ORIGIN="$(url_origin "${OLD_AI_URL:-https://api.deepseek.com/v1}")"

# ---- Step 1: TELEGRAM_BOT_TOKEN (required, hidden echo) ----
printf '[1/4] 填写 Telegram Bot Token（必填 · 输入时不显示明文）\n'
printf '      获取方式：Telegram 找 @BotFather 发 /newbot，记得再发 /setprivacy -> Disable\n'
BOT_TOKEN=""
while true; do
  if [[ -n "$OLD_TOKEN" ]]; then
    printf '      当前已保存：%s（直接回车保留）\n' "$(mask_secret "$OLD_TOKEN")"
  fi
  prompt_secret '  👉 请输入 TELEGRAM_BOT_TOKEN（隐藏输入）: ' INPUT_TOKEN
  if [[ -z "$INPUT_TOKEN" && -n "$OLD_TOKEN" ]]; then
    BOT_TOKEN="$OLD_TOKEN"
    break
  fi
  if is_valid_token "$INPUT_TOKEN"; then
    BOT_TOKEN="$INPUT_TOKEN"
    printf '  🔒 已接收 Bot Token：%s\n' "$(mask_secret "$BOT_TOKEN")"
    break
  fi
  printf '  ⚠️  格式不正确！Bot Token 应类似 1234567890:AAFxxxxxxxxxxxxxxxx（不能含空格），请重新输入。\n'
done

BOT_USERNAME=""
if BOT_USERNAME="$(tg_fetch_bot_username "$BOT_TOKEN" || true)" && [[ -n "$BOT_USERNAME" ]]; then
  printf '  %s直达链接%s   %shttps://t.me/%s%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$BOT_USERNAME" "$C_RESET"
elif BOT_USERNAME="$(read_cached_bot_username "$BOT_TOKEN" || true)" && [[ -n "$BOT_USERNAME" ]]; then
  printf '  %s直达链接%s   %shttps://t.me/%s%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$BOT_USERNAME" "$C_RESET"
fi

printf '\n'

# ---- Step 2: OWNER_IDS (strongly recommended) ----
printf '[2/4] 填写超级管理员纯数字 User ID（强烈建议）\n'
printf '      获取方式：Telegram 私聊 @userinfobot（或 @MissRose_bot 发 /id），注意是纯数字，不是 @用户名\n'
printf '      （多个超管用英文逗号分隔；直接回车跳过也可，启动后 15 分钟内可从日志复制 /claim 口令认领）\n'
OWNER_IDS=""
while true; do
  if [[ -n "$OLD_OWNERS" ]]; then
    printf '      当前已保存：%s（直接回车保留，输入 - 清空）\n' "$OLD_OWNERS"
  fi
  prompt_line '  👉 请输入 OWNER_IDS: ' INPUT_OWNERS
  if [[ "$INPUT_OWNERS" == "-" ]]; then
    OWNER_IDS=""
    break
  fi
  if [[ -z "$INPUT_OWNERS" ]]; then
    OWNER_IDS="$OLD_OWNERS"
    break
  fi
  if [[ "$INPUT_OWNERS" == *@* ]]; then
    printf '  ⚠️  检测到 @用户名！这里必须填纯数字 User ID（找 @userinfobot 获取），请重新输入。\n'
    continue
  fi
  if is_valid_owner_ids "$INPUT_OWNERS"; then
    OWNER_IDS="${INPUT_OWNERS// /}"
    break
  fi
  printf '  ⚠️  格式不正确！请输入纯数字 ID（如 123456789 或 123456789,987654321），或直接回车跳过。\n'
done

printf '\n'

# ---- Step 3: Optional AI API setup (Terminal OR later in Telegram /start) ----
AI_API_KEY="${OLD_AI_KEY}"
AI_BASE_URL="${OLD_AI_URL:-https://api.deepseek.com/v1}"
AI_MODEL="${OLD_AI_MODEL:-deepseek-flash}"

printf '[3/4] 配置 AI 大模型 API Key（可选，留空也可先以基础硬防模式启动）\n'
if [[ -n "$OLD_AI_KEY" ]]; then
  printf '      当前已保存：%s | %s | Key: %s\n' "$AI_MODEL" "$(sanitize_url "$AI_BASE_URL")" "$(mask_secret "$OLD_AI_KEY")"
fi
printf '      [1] 稍后私聊机器人 /start 点按钮填写 AI Key（推荐 · 马上启动）\n'
printf '      [2] 现在在终端里直接配置 AI 接口 / 模型 / Key\n'
prompt_line '  👉 请选择 [1/2，默认 1]: ' AI_CHOICE

if [[ "$AI_CHOICE" == "2" ]]; then
  printf '\n      选择模型接口预设（支持任意 OpenAI 兼容接口）：\n'
  printf '        1) DeepSeek   (https://api.deepseek.com/v1 | deepseek-flash)\n'
  printf '        2) OpenAI     (https://api.openai.com/v1 | gpt-5-mini)\n'
  printf '        3) Gemini     (https://generativelanguage.googleapis.com/v1beta/openai/ | gemini-2.5-flash)\n'
  printf '        4) OpenRouter (https://openrouter.ai/api/v1 | google/gemini-2.5-flash)\n'
  printf '        5) 自定义 OpenAI 兼容地址与模型名\n'
  prompt_line '  👉 请选择预设 [1-5，默认 1]: ' PRESET
  case "${PRESET:-1}" in
    1)
      AI_BASE_URL="https://api.deepseek.com/v1"
      AI_MODEL="deepseek-flash"
      ;;
    2)
      AI_BASE_URL="https://api.openai.com/v1"
      AI_MODEL="gpt-5-mini"
      ;;
    3)
      AI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
      AI_MODEL="gemini-2.5-flash"
      ;;
    4)
      AI_BASE_URL="https://openrouter.ai/api/v1"
      AI_MODEL="google/gemini-2.5-flash"
      ;;
    5)
      while true; do
        prompt_line "  👉 请输入 AI_BASE_URL（远程需 https://）[当前: $(sanitize_url "$AI_BASE_URL")]: " IN_URL
        [[ -z "$IN_URL" ]] && IN_URL="$AI_BASE_URL"
        if is_valid_base_url "$IN_URL"; then
          AI_BASE_URL="$IN_URL"
          break
        fi
        printf '  ⚠️  远程接口必须使用 https://（且不可含账号密码或查询参数）；仅本机 localhost/127.0.0.1/host.docker.internal 允许 http://。\n'
      done
      prompt_line "  👉 请输入 AI_MODEL [当前: ${AI_MODEL}]: " IN_MODEL
      [[ -n "$IN_MODEL" ]] && AI_MODEL="$IN_MODEL"
      ;;
    *)
      printf '  ℹ️  已使用默认 DeepSeek 预设。\n'
      AI_BASE_URL="https://api.deepseek.com/v1"
      AI_MODEL="deepseek-flash"
      ;;
  esac

  if [[ "${PRESET:-1}" != "5" ]]; then
    prompt_line "  👉 模型名 [回车默认 ${AI_MODEL}]: " CUSTOM_MODEL
    [[ -n "$CUSTOM_MODEL" ]] && AI_MODEL="$CUSTOM_MODEL"
  fi

  NEW_AI_ORIGIN="$(url_origin "$AI_BASE_URL")"
  ORIGIN_CHANGED=0
  if [[ -n "$OLD_AI_KEY" && "$NEW_AI_ORIGIN" != "$OLD_AI_ORIGIN" ]]; then
    ORIGIN_CHANGED=1
    AI_API_KEY=""
    printf '  🔒 检测到服务商主机已变更（%s -> %s），已自动清空旧 API Key 防止凭据外发！\n' "$(sanitize_url "$OLD_AI_ORIGIN")" "$(sanitize_url "$NEW_AI_ORIGIN")"
  elif [[ -n "$OLD_AI_KEY" ]]; then
    printf '      当前已保存 Key：%s（直接回车保留，输入 - 清空）\n' "$(mask_secret "$OLD_AI_KEY")"
  fi

  prompt_secret '  👉 请输入 AI_API_KEY（隐藏输入；可回车留空稍后在机器人私聊填写）: ' IN_KEY
  if [[ "$IN_KEY" == "-" ]]; then
    AI_API_KEY=""
  elif [[ -n "$IN_KEY" ]]; then
    AI_API_KEY="$IN_KEY"
    printf '  🔒 已接收 AI API Key：%s\n' "$(mask_secret "$AI_API_KEY")"
  elif (( ORIGIN_CHANGED == 1 )); then
    AI_API_KEY=""
  fi
fi

# ---- Step 4: Optional one-click AI-智能广告杀手 bot avatar / name / description ----
printf '\n'
printf '[4/4] 是否将机器人头像、名称与简介一键替换为「AI-智能广告杀手」？\n'
printf '      • 名称：%s\n' "$BOT_DEFAULT_NAME"
printf '      • 头像：官方AI-智能广告杀手图标 (assets/avatar.jpg)\n'
printf '      • 简介：%s\n' "$BOT_DEFAULT_SHORT_DESC"
printf '      （稍后也可在机器人私聊 /start 里随时一键更换或自定义）\n'
APPLY_BRAND="n"
prompt_line '  👉 立即替换为AI-智能广告杀手头像/名称/简介？[y/N]: ' APPLY_BRAND

# ---- Detect Docker Compose & ask launch confirmation BEFORE writing .env ----
# Asking all prompts before committing .env guarantees EOF at ANY prompt never mutates disk or starts services!
detect_compose_cmd

DO_START="n"
if (( ${#COMPOSE_CMD[@]} > 0 )); then
  printf '\n'
  prompt_line '🚀 保存配置后是否立即构建并启动AI-智能广告杀手？[Y/n]: ' DO_START
fi

# ---- Final safety gates right before committing .env ----
if ! verify_adkiller_dir "$WORK_DIR"; then
  printf '❌ 目标目录 %s 未通过 AI-智能广告杀手 身份校验，已中止写入 .env。\n' "$WORK_DIR" >&2
  exit 1
fi
if ! is_valid_base_url "$AI_BASE_URL"; then
  printf '⚠️  最终校验发现不合规的 AI 接口地址（%s），已清空旧 Key 并重置为 https://api.deepseek.com/v1。\n' "$(sanitize_url "$AI_BASE_URL")" >&2
  AI_BASE_URL="https://api.deepseek.com/v1"
  AI_API_KEY=""
fi

# ---- Preserve any extra custom settings from existing .env ----
EXTRA_LINES=""
if [[ -f "$ENV_FILE" ]]; then
  EXTRA_LINES="$(grep -Ev '^[[:space:]]*(#|$|TELEGRAM_BOT_TOKEN=|OWNER_IDS=|AI_API_KEY=|AI_BASE_URL=|AI_MODEL=)' "$ENV_FILE" || true)"
fi

# ---- Write .env atomically with 0600 permissions (scoped umask so later steps stay unaffected) ----
TMP_ENV="${ENV_FILE}.tmp.$$"
(
  umask 077
  {
    printf '# Generated by AI-智能广告杀手 setup.sh\n'
    printf 'TELEGRAM_BOT_TOKEN=%s\n' "$BOT_TOKEN"
    printf 'OWNER_IDS=%s\n' "$OWNER_IDS"
    printf 'AI_API_KEY=%s\n' "$AI_API_KEY"
    printf 'AI_BASE_URL=%s\n' "$AI_BASE_URL"
    printf 'AI_MODEL=%s\n' "$AI_MODEL"
    if [[ -n "$EXTRA_LINES" ]]; then
      printf '\n# Preserved custom settings\n'
      printf '%s\n' "$EXTRA_LINES"
    fi
  } > "$TMP_ENV"
  chmod 600 "$TMP_ENV"
)
mv -f "$TMP_ENV" "$ENV_FILE"

if [[ -n "$BOT_USERNAME" ]]; then
  save_cached_bot_username "$BOT_TOKEN" "$BOT_USERNAME"
fi

printf '\n✅ 配置已安全写入 %s（权限 600）！\n' "$ENV_FILE"
if [[ -n "$BOT_USERNAME" ]]; then
  printf '  %s机器人直达链接%s  %shttps://t.me/%s%s\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$BOT_USERNAME" "$C_RESET"
fi

# ---- Apply AI-智能广告杀手 avatar / name / description if requested ----
if [[ "$APPLY_BRAND" =~ ^[Yy]$ ]]; then
  apply_bot_branding_cli "$BOT_TOKEN"
fi

# ---- Install `adkiller` terminal shortcut AFTER config is safely committed ----
install_cli_shortcut

# ---- Optionally launch Docker Compose ----
if (( ${#COMPOSE_CMD[@]} > 0 )); then
  if [[ -z "$DO_START" || "$DO_START" =~ ^[Yy]$ ]]; then
    (cd "$WORK_DIR" && "${COMPOSE_CMD[@]}" up -d --build --force-recreate)
    printf '\n'
    box_top
    box_center "AI-智能广告杀手已启动" "${C_YELLOW_BOLD}AI-智能广告杀手已启动${C_RESET}"
    box_bottom
    if [[ -n "$BOT_USERNAME" ]]; then
      printf '  %s直达链接%s   %shttps://t.me/%s%s\n\n' "$C_CYAN" "$C_RESET" "$C_WHITE" "$BOT_USERNAME" "$C_RESET"
    fi
    if [[ -n "$OWNER_IDS" ]]; then
      if [[ -n "$BOT_USERNAME" ]]; then
        printf '1. 点击上方链接打开机器人发送 /start：https://t.me/%s\n' "$BOT_USERNAME"
      else
        printf '1. 打开 Telegram 私聊你的机器人发送 /start\n'
      fi
      printf '2. 可一键配置 AI 接口/Key，或点「🛡 更换机器人头像 / 名称 / 简介」\n'
      printf '3. 拉机器人进群设为管理员（删消息 + 封禁用户），群内发 /config 点按钮管理\n'
    else
      printf '1. 你未填写 OWNER_IDS，运行下方命令查看 15 分钟一次性认领口令：\n'
      printf '     cd %s && %s logs | grep "/claim"\n' "$WORK_DIR" "${COMPOSE_CMD[*]}"
      if [[ -n "$BOT_USERNAME" ]]; then
        printf '2. 打开 https://t.me/%s 发送 /claim <口令> 认领，再发 /start 即可点按钮配置！\n' "$BOT_USERNAME"
      else
        printf '2. 私聊机器人发送 /claim <口令> 完成认领，再发 /start 即可点按钮配置！\n'
      fi
    fi
    printf '\n常用终端命令：adkiller（菜单）| adkiller config（配置）| adkiller brand（换头像）| adkiller logs（日志）\n'
    exit 0
  fi
else
  printf '\nℹ️  当前系统未检测到 docker compose，请先安装 Docker 后再执行：\n'
  printf '     adkiller start  （或 cd %s && docker compose up -d --build）\n' "$WORK_DIR"
fi

printf '\n后续随时在终端输入 adkiller 即可进入配置与管理，或在机器人私聊 /start 点按钮更新。\n'
