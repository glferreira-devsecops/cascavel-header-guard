#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 🛡️ Cascavel Header Guard v1.0.0
# HTTP Security Headers Analyzer for CI/CD
# Copyright (c) 2026 RET Tecnologia — https://rettecnologia.org
# License: MIT
# ─────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
URLS="${INPUT_URLS}"
FAIL_SCORE="${INPUT_FAIL_SCORE:-50}"
FAIL_CRITICAL="${INPUT_FAIL_CRITICAL:-true}"
TIMEOUT="${INPUT_TIMEOUT:-10}"
FOLLOW="${INPUT_FOLLOW:-true}"
UA="${INPUT_UA:-Cascavel-HeaderGuard/1.0}"

REPORT_DIR="${GITHUB_WORKSPACE:-.}/.cascavel"
REPORT_JSON="${REPORT_DIR}/headers-report.json"
mkdir -p "$REPORT_DIR"

CURL_OPTS="-sS --max-time ${TIMEOUT} -A '${UA}' -D -"
[ "$FOLLOW" = "true" ] && CURL_OPTS="$CURL_OPTS -L"

# ─── Header Database ─────────────────────────────────────
# Format: HEADER_NAME|WEIGHT|CATEGORY|DESCRIPTION|RECOMMENDED
declare -a HEADERS_DB=(
  # ── CRITICAL (high weight) ──
  "strict-transport-security|15|critical|Enforces HTTPS connections|max-age=31536000; includeSubDomains; preload"
  "content-security-policy|15|critical|Prevents XSS and injection attacks|default-src 'self'"
  "x-content-type-options|10|critical|Prevents MIME-type sniffing|nosniff"
  
  # ── HIGH ──
  "x-frame-options|8|high|Prevents clickjacking attacks|DENY or SAMEORIGIN"
  "referrer-policy|7|high|Controls referrer information|strict-origin-when-cross-origin"
  "permissions-policy|7|high|Controls browser features/APIs|camera=(), microphone=(), geolocation=()"
  "x-xss-protection|5|high|Legacy XSS filter (deprecated but scored)|0 (disabled) or 1; mode=block"
  "cross-origin-opener-policy|6|high|Isolates browsing context|same-origin"
  "cross-origin-resource-policy|6|high|Controls cross-origin resource loading|same-origin"
  "cross-origin-embedder-policy|5|high|Controls embedding behavior|require-corp"
  
  # ── MEDIUM ──
  "x-dns-prefetch-control|3|medium|Controls DNS prefetching|off"
  "x-download-options|3|medium|IE download options|noopen"
  "x-permitted-cross-domain-policies|3|medium|Adobe cross-domain policy|none"
  "cache-control|4|medium|Cache directives for sensitive pages|no-store, no-cache"
  
  # ── INFORMATIONAL ──
  "server|2|info|Server identification (should be minimal)|Should not reveal version"
  "x-powered-by|2|info|Technology disclosure (should be absent)|Should be REMOVED"
)

MAX_POSSIBLE_SCORE=0
for entry in "${HEADERS_DB[@]}"; do
  IFS='|' read -r _ weight _ _ _ <<< "$entry"
  ((MAX_POSSIBLE_SCORE += weight))
done

# ─── Banner ───────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  🛡️  CASCAVEL HEADER GUARD v${VERSION}              ║"
echo "  ║  HTTP Security Headers Analyzer                  ║"
echo "  ║  RET Tecnologia · https://rettecnologia.org      ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# ─── Analyze Function ────────────────────────────────────
analyze_url() {
  local url="$1"
  local score=0
  local missing_critical=0
  local total_present=0
  local total_missing=0
  local issues=""
  
  echo "  🔗 Scanning: ${url}"
  echo "  ────────────────────────────────────────────────────"
  
  # Fetch headers
  RESPONSE=$(curl $CURL_OPTS -o /dev/null "$url" 2>/dev/null || echo "CURL_FAILED")
  
  if [ "$RESPONSE" = "CURL_FAILED" ]; then
    echo "  ❌ Failed to connect to ${url}"
    echo ""
    return 1
  fi
  
  # Extract HTTP status
  HTTP_STATUS=$(echo "$RESPONSE" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")
  echo "  📡 HTTP Status: ${HTTP_STATUS}"
  echo ""
  
  # Normalize headers to lowercase for matching
  HEADERS_LOWER=$(echo "$RESPONSE" | tr '[:upper:]' '[:lower:]')
  
  for entry in "${HEADERS_DB[@]}"; do
    IFS='|' read -r header weight category desc recommended <<< "$entry"
    
    # Special handling for "should be absent" headers
    if [ "$header" = "x-powered-by" ]; then
      if echo "$HEADERS_LOWER" | grep -qi "^x-powered-by:"; then
        VALUE=$(echo "$RESPONSE" | grep -i "^x-powered-by:" | head -1 | cut -d: -f2- | xargs)
        echo "  🔴 x-powered-by: ${VALUE} (REMOVE THIS — leaks technology)"
        ((total_missing++))
      else
        echo "  ✅ x-powered-by: Not present (good!)"
        ((score += weight))
        ((total_present++))
      fi
      continue
    fi
    
    if [ "$header" = "server" ]; then
      if echo "$HEADERS_LOWER" | grep -qi "^server:"; then
        VALUE=$(echo "$RESPONSE" | grep -i "^server:" | head -1 | cut -d: -f2- | xargs)
        # Check if it reveals version info
        if echo "$VALUE" | grep -qP '[0-9]+\.[0-9]+'; then
          echo "  🟠 server: ${VALUE} (reveals version — minimize this)"
          ((score += weight / 2))
        else
          echo "  🟡 server: ${VALUE}"
          ((score += weight))
        fi
        ((total_present++))
      else
        echo "  ✅ server: Not present (good!)"
        ((score += weight))
        ((total_present++))
      fi
      continue
    fi

    # Normal header check (should be present)
    if echo "$HEADERS_LOWER" | grep -qi "^${header}:"; then
      VALUE=$(echo "$RESPONSE" | grep -i "^${header}:" | head -1 | cut -d: -f2- | xargs)
      
      # Validate header value quality
      QUALITY="✅"
      BONUS=0
      
      case "$header" in
        strict-transport-security)
          MAX_AGE=$(echo "$VALUE" | grep -oP 'max-age=\K[0-9]+' || echo 0)
          if [ "${MAX_AGE:-0}" -ge 31536000 ]; then
            BONUS=2
            echo "$VALUE" | grep -qi "includesubdomains" && BONUS=3
            echo "$VALUE" | grep -qi "preload" && BONUS=5
          elif [ "${MAX_AGE:-0}" -lt 2592000 ]; then
            QUALITY="🟡"
            BONUS=-2
          fi
          ;;
        content-security-policy)
          echo "$VALUE" | grep -qi "unsafe-inline" && QUALITY="🟠" && BONUS=-3
          echo "$VALUE" | grep -qi "unsafe-eval" && QUALITY="🟠" && BONUS=-5
          [ ${#VALUE} -gt 20 ] && BONUS=$((BONUS + 2))
          ;;
        x-frame-options)
          echo "$VALUE" | grep -qi "allow-from" && QUALITY="🟠" && BONUS=-2
          ;;
      esac
      
      echo "  ${QUALITY} ${header}: $(echo "$VALUE" | cut -c1-70)"
      ((score += weight + BONUS)) || true
      [ $score -lt 0 ] && score=0
      ((total_present++))
    else
      # Header missing
      case "$category" in
        critical)
          echo "  🔴 ${header}: MISSING [${category^^}] — ${desc}"
          ((missing_critical++))
          ;;
        high)
          echo "  🟠 ${header}: MISSING [${category^^}] — ${desc}"
          ;;
        medium)
          echo "  🟡 ${header}: MISSING — ${desc}"
          ;;
        *)
          echo "  🔵 ${header}: not set"
          ;;
      esac
      ((total_missing++))
    fi
  done
  
  # Calculate percentage score
  PERCENT=$((score * 100 / MAX_POSSIBLE_SCORE))
  [ $PERCENT -gt 100 ] && PERCENT=100
  [ $PERCENT -lt 0 ] && PERCENT=0
  
  # Grade
  GRADE="F"
  GRADE_COLOR="🔴"
  [ $PERCENT -ge 20 ] && GRADE="D" && GRADE_COLOR="🟠"
  [ $PERCENT -ge 40 ] && GRADE="C" && GRADE_COLOR="🟡"
  [ $PERCENT -ge 60 ] && GRADE="B" && GRADE_COLOR="🟢"
  [ $PERCENT -ge 80 ] && GRADE="A" && GRADE_COLOR="✅"
  [ $PERCENT -ge 95 ] && GRADE="A+" && GRADE_COLOR="🏆"
  
  echo ""
  echo "  ────────────────────────────────────────────────────"
  echo "  ${GRADE_COLOR} Score: ${PERCENT}/100 (Grade: ${GRADE})"
  echo "  📊 Present: ${total_present} | Missing: ${total_missing} | Critical missing: ${missing_critical}"
  echo ""
  
  # Return values via temp files
  echo "$PERCENT" >> "${REPORT_DIR}/.scores"
  echo "$missing_critical" >> "${REPORT_DIR}/.critical"
  
  # JSON entry
  cat >> "${REPORT_DIR}/.results" << JEOF
    {"url":"${url}","score":${PERCENT},"grade":"${GRADE}","present":${total_present},"missing":${total_missing},"missing_critical":${missing_critical}},
JEOF
}

# ─── Main Scan Loop ───────────────────────────────────────
> "${REPORT_DIR}/.scores"
> "${REPORT_DIR}/.critical"
> "${REPORT_DIR}/.results"

IFS=',' read -ra URL_LIST <<< "$URLS"
URL_COUNT=${#URL_LIST[@]}

echo "  🎯 Targets: ${URL_COUNT} URL(s)"
echo "  ⏱️  Timeout: ${TIMEOUT}s"
echo "  📏 Min score: ${FAIL_SCORE}/100"
echo ""

for url in "${URL_LIST[@]}"; do
  url=$(echo "$url" | xargs)
  [ -z "$url" ] && continue
  analyze_url "$url"
done

# ─── Calculate Totals ────────────────────────────────────
TOTAL_SCORE=0
WORST_SCORE=100
TOTAL_CRITICAL=0
COUNT=0

while IFS= read -r s; do
  [ -z "$s" ] && continue
  ((TOTAL_SCORE += s))
  ((COUNT++))
  [ "$s" -lt "$WORST_SCORE" ] && WORST_SCORE=$s
done < "${REPORT_DIR}/.scores"

while IFS= read -r c; do
  [ -z "$c" ] && continue
  ((TOTAL_CRITICAL += c))
done < "${REPORT_DIR}/.critical"

[ $COUNT -gt 0 ] && AVG_SCORE=$((TOTAL_SCORE / COUNT)) || AVG_SCORE=0

# ─── Generate Report ─────────────────────────────────────
RESULTS_JSON=$(cat "${REPORT_DIR}/.results" | sed '$ s/,$//')

cat > "$REPORT_JSON" << JSONEOF
{
  "scanner": "cascavel-header-guard",
  "version": "${VERSION}",
  "vendor": "RET Tecnologia",
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "urls_scanned": ${COUNT},
    "average_score": ${AVG_SCORE},
    "worst_score": ${WORST_SCORE},
    "missing_critical_total": ${TOTAL_CRITICAL}
  },
  "results": [
${RESULTS_JSON}
  ]
}
JSONEOF

# ─── Summary ──────────────────────────────────────────────
echo "  ══════════════════════════════════════════════════════"
echo "  📊 OVERALL RESULTS"
echo "  ──────────────────────────────────────────────────────"
echo "  🎯 URLs scanned:       ${COUNT}"
echo "  📈 Average score:      ${AVG_SCORE}/100"
echo "  📉 Worst score:        ${WORST_SCORE}/100"
echo "  🔴 Missing critical:   ${TOTAL_CRITICAL}"
echo "  📄 Report:             ${REPORT_JSON}"
echo "  ══════════════════════════════════════════════════════"
echo ""

# ─── GitHub Outputs ───────────────────────────────────────
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "total-score=${AVG_SCORE}" >> "$GITHUB_OUTPUT"
  echo "worst-score=${WORST_SCORE}" >> "$GITHUB_OUTPUT"
  echo "missing-critical=${TOTAL_CRITICAL}" >> "$GITHUB_OUTPUT"
  echo "report-path=${REPORT_JSON}" >> "$GITHUB_OUTPUT"
fi

# ─── GitHub Step Summary ──────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat >> "$GITHUB_STEP_SUMMARY" << SUMMARYEOF
### 🛡️ Cascavel Header Guard Results

| Metric | Value |
|:-------|------:|
| URLs scanned | ${COUNT} |
| Average score | ${AVG_SCORE}/100 |
| Worst score | ${WORST_SCORE}/100 |
| Missing critical headers | ${TOTAL_CRITICAL} |

> Powered by [RET Tecnologia](https://rettecnologia.org) · Cascavel Header Guard v${VERSION}
SUMMARYEOF
fi

# ─── Cleanup ──────────────────────────────────────────────
rm -f "${REPORT_DIR}/.scores" "${REPORT_DIR}/.critical" "${REPORT_DIR}/.results"

# ─── Exit Logic ───────────────────────────────────────────
FAILED=false

if [ "$FAIL_CRITICAL" = "true" ] && [ "$TOTAL_CRITICAL" -gt 0 ]; then
  echo "  ❌ FAIL: ${TOTAL_CRITICAL} critical header(s) missing"
  FAILED=true
fi

if [ "$WORST_SCORE" -lt "$FAIL_SCORE" ]; then
  echo "  ❌ FAIL: Score ${WORST_SCORE} is below minimum ${FAIL_SCORE}"
  FAILED=true
fi

echo ""
echo "  🛡️ Cascavel Header Guard by RET Tecnologia"
echo ""

if [ "$FAILED" = true ]; then
  exit 1
else
  echo "  ✅ All URLs passed security header checks!"
fi
