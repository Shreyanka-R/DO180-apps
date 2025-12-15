#!/usr/bin/env bash
set -euo pipefail

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"
CSV_FILE="linux_audit_report_$(hostname)_$(date +%F_%H%M).csv"

HOST=$(hostname)
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$HOST_IP" ] && HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
OS_NAME=$( ( [ -f /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME" ) || echo "Unknown OS" )
MODE="Read-only Audit"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

csv_escape() { printf '%s' "$1" | sed 's/\"/\"\"/g'; }

SYSTEM_DETAILS="Hostname=$HOST | HostIP=$HOST_IP | OS=$OS_NAME | Mode=$MODE | Timestamp=$TIMESTAMP"

# =============================================================
# CSV HEADER
# =============================================================
printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
  "System Details" \
  "Audit Check" \
  "Risk Description" \
  "Risk Category" \
  "Risk Level" \
  "Expected Control" \
  "Observation" \
  "Status" \
  "Recommended Action" \
  > "$CSV_FILE"

# =============================================================
# Risk mapping
# =============================================================
risk_map() {
  case "$1" in
    *Shadow*|*Password*)
      if [ "$status" = "FAIL" ]; then
        echo "Passwords are not protected using shadow file; credential hashes may be exposed|Identity & Access Management|Critical"
      else
        echo "Passwords are protected using shadow file|Identity & Access Management|High"
      fi
      ;;
    *Root*)
      echo "Unrestricted root access increases risk of privilege abuse|Authentication Security|Critical"
      ;;
    *Port*|*Listening*)
      echo "Legacy or insecure network services may expose credentials in clear text|Network Protocol Security|High"
      ;;
    *SSH*)
      echo "Weak SSH configuration may allow unauthorized remote access|Remote Access Management|Medium"
      ;;
    *Root*)
      echo "Unrestricted root access increases risk of privilege abuse|Authentication Security|Critical"
      ;;
    *Trust*|*.rhosts*)
      echo "Trusted relationships may allow password-less unauthorized access|Trust / Authentication Risk|High"
      ;;
    *SUID*|*SGID*)
      echo "Excessive privileged binaries may allow privilege escalation|Privilege Management|High"
      ;;
    *)
      echo "Security misconfiguration may impact confidentiality, integrity, or availability|System Security|Medium"
      ;;
  esac
}
add_audit_row() {
  local check="$1" expected="$2" obs="$3" status="$4" remediation="$5"
  IFS='|' read -r RISK_DESC RISK_CAT RISK_LEVEL <<< "$(risk_map "$check")"

  printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$(csv_escape "$SYSTEM_DETAILS")" \
    "$(csv_escape "$check")" \
    "$(csv_escape "$RISK_DESC")" \
    "$(csv_escape "$RISK_CAT")" \
    "$(csv_escape "$RISK_LEVEL")" \
    "$(csv_escape "$expected")" \
    "$(csv_escape "$obs")" \
    "$(csv_escape "$status")" \
    "$(csv_escape "$remediation")" \
    >> "$CSV_FILE"
}
CMD_OUT=""
run_cmd() { CMD_OUT=$(sh -c "$1" 2>/dev/null || true); }
echo -e "${BLUE}Starting Linux Security Audit...${RESET}"

# ----------------------------------------------------------
# CHECK 1: Use of Shadow Password File
# ----------------------------------------------------------
CHECK="Use of Shadow Password File"
EXPECTED="Passwords must not be stored in /etc/passwd and permissions on /etc/passwd and /etc/shadow must be secure"
STATUS="PASS"
REM="None"
DETAILS=""
# -------------------------
# Shadow password usage
# -------------------------
CMD="awk -F: '{print \$1 \":\" \$2}' /etc/passwd"
run_cmd "$CMD"
PASSWD_FIELDS="$CMD_OUT"
NON_SHADOW=$(echo "$PASSWD_FIELDS" | grep -Ev '^[^:]+:x$' || true)
if [ -n "$NON_SHADOW" ]; then
  STATUS="FAIL"
  REM="Ensure shadow passwords are enabled and no password hashes exist in /etc/passwd"
  DETAILS+="Users not using shadow passwords:
$NON_SHADOW

"
else
  DETAILS+="All users are using shadow passwords

"
fi

# -------------------------
# /etc/passwd permissions
# -------------------------
CMD="ls -l /etc/passwd"
run_cmd "$CMD"
PASSWD_LS="$CMD_OUT"
PASSWD_PERM=$(stat -c "%a" /etc/passwd 2>/dev/null || stat -f "%Lp" /etc/passwd)
PASSWD_OWNER=$(stat -c "%U:%G" /etc/passwd 2>/dev/null || stat -f "%Su:%Sg" /etc/passwd)
DETAILS+="/etc/passwd:
$PASSWD_LS
"

if [ "$PASSWD_PERM" != "644" ] || [ "$PASSWD_OWNER" != "root:root" ]; then
  STATUS="FAIL"
  REM="Run: chown root:root /etc/passwd && chmod 644 /etc/passwd"
  DETAILS+="Permissions or ownership on /etc/passwd are incorrect

"
else
  DETAILS+="Permissions and ownership on /etc/passwd are correct

"
fi

# -------------------------
# /etc/shadow permissions
# -------------------------
CMD="ls -l /etc/shadow"
run_cmd "$CMD"
SHADOW_LS="$CMD_OUT"
SHADOW_PERM=$(stat -c "%a" /etc/shadow 2>/dev/null || stat -f "%Lp" /etc/shadow)
SHADOW_OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null || stat -f "%Su:%Sg" /etc/shadow)
DETAILS+="/etc/shadow:
$SHADOW_LS
"

if [ "$SHADOW_PERM" != "640" ] || [ "$SHADOW_OWNER" != "root:shadow" ]; then
  STATUS="FAIL"
  REM="Run: chown root:shadow /etc/shadow && chmod 640 /etc/shadow"
  DETAILS+="Permissions or ownership on /etc/shadow are incorrect
"
else
  DETAILS+="Permissions and ownership on /etc/shadow are correct
"
fi
# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Shadow password usage and file permissions are correctly configured"
else
  SUMMARY="Issues detected with shadow password usage or file permissions"
fi
OBS="$SUMMARY

Commands executed:
- awk -F: '{print user:password_field}' /etc/passwd
- ls -l /etc/passwd
- ls -l /etc/shadow

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 2: System Accounts Password Lock and NIS Usage
# ----------------------------------------------------------
CHECK="System Accounts Password Lock and NIS Usage"
EXPECTED="System accounts must be locked and NIS must not be installed, enabled, or configured unless explicitly required"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- cat /etc/shadow
- systemctl list-unit-files
- grep nis /etc/nsswitch.conf"
SYSTEM_ACCOUNTS="daemon|bin|sys|adm|uucp|guest|nobody|lpd"
CMD="awk -F: '\$1 ~ /^(daemon|bin|sys|adm|uucp|guest|nobody|lpd)\$/ {print \$1 \":\" \$2 \":\" \$7}' /etc/passwd"
run_cmd "$CMD"
PASSWD_SYS_OUT="$CMD_OUT"
DETAILS+="System accounts from /etc/passwd (user:password:shell):
${PASSWD_SYS_OUT:-<none>}

"

# -------------------------
# Verify password lock in /etc/shadow
# -------------------------
CMD="awk -F: '\$1 ~ /^(daemon|bin|sys|adm|uucp|guest|nobody|lpd)\$/ {print \$1 \":\" \$2}' /etc/shadow 2>/dev/null"
run_cmd "$CMD"
SHADOW_SYS_OUT="$CMD_OUT"

UNLOCKED_ACCTS=$(echo "$SHADOW_SYS_OUT" | grep -Ev ':[!*]' || true)
if [ -n "$SHADOW_SYS_OUT" ]; then
  DETAILS+="System accounts from /etc/shadow (user:password_field):
$SHADOW_SYS_OUT

"
else
  DETAILS+="System accounts from /etc/shadow:
All system accounts are locked (! or *)

"
fi

if [ -n "$UNLOCKED_ACCTS" ]; then
  STATUS="FAIL"
  REM="Lock system accounts using usermod -L <user> or set password field to ! or *"
  DETAILS+="Unlocked system accounts detected:
$UNLOCKED_ACCTS

"
fi

# -------------------------
# NIS detection – services
# -------------------------
if systemctl list-unit-files 2>/dev/null | grep -qE 'ypserv|ypbind'; then
  STATUS="REVIEW"
  REM="Verify NIS usage is required; disable ypserv/ypbind if not needed"
  DETAILS+="NIS services detected:
ypserv / ypbind present

"
else
  DETAILS+="NIS services:
Not installed or not enabled

"
fi

# -------------------------
# NIS detection – configuration
# -------------------------
if grep -q '^nis:' /etc/nsswitch.conf 2>/dev/null; then
  STATUS="REVIEW"
  REM="Remove NIS configuration from /etc/nsswitch.conf if not required"
  DETAILS+="NIS configuration detected in /etc/nsswitch.conf

"
else
  DETAILS+="NIS configuration:
Not present in /etc/nsswitch.conf

"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="System accounts are locked and NIS is not installed, enabled, or configured"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="NIS components detected; review required"
else
  SUMMARY="One or more system accounts are not properly locked"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 3: Trusted Host Access (/etc/hosts.equiv)
# ----------------------------------------------------------
CHECK="Trusted Host Access (/etc/hosts.equiv)"
EXPECTED="/etc/hosts.equiv must not allow broad trust; if present it must be owned by root, permission 600, and contain only specific trusted entries"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/hosts.equiv
- ls -l /etc/hosts.equiv"
HOSTS_EQUIV="/etc/hosts.equiv"

# -------------------------
# File existence and content
# -------------------------
if [ -f "$HOSTS_EQUIV" ]; then
  CMD="cat $HOSTS_EQUIV"
  run_cmd "$CMD"
  HOSTS_CONTENT="$CMD_OUT"

  DETAILS+="/etc/hosts.equiv contents:
${HOSTS_CONTENT:-<empty>}

"

  CMD="ls -l $HOSTS_EQUIV"
  run_cmd "$CMD"
  DETAILS+="File listing:
$CMD_OUT

"
else
  DETAILS+="/etc/hosts.equiv file not present; trusted host access is not configured

"
fi

# -------------------------
# Insecure '+' trust check
# -------------------------
if [ -f "$HOSTS_EQUIV" ] && grep -qE '^[[:space:]]*\+' "$HOSTS_EQUIV"; then
  STATUS="FAIL"
  REM="Remove '+' entries which trust all hosts"
  DETAILS+="Insecure configuration detected:
File contains '+' entry allowing trust of all hosts

"
fi

# -------------------------
# Entry format validation
# -------------------------
if [ -f "$HOSTS_EQUIV" ]; then
  INVALID_ENTRIES=$(grep -Ev '^[[:space:]]*($|#|[A-Za-z0-9.-]+\.[A-Za-z]{2,}[[:space:]]+[A-Za-z0-9._-]+)' "$HOSTS_EQUIV" || true)

  if [ -n "$INVALID_ENTRIES" ]; then
    STATUS="REVIEW"
    REM="Ensure entries contain fully qualified hostname followed by username"
    DETAILS+="Non-standard entries detected:
$INVALID_ENTRIES

"
  fi
fi

# -------------------------
# Ownership and permission check
# -------------------------
if [ -f "$HOSTS_EQUIV" ]; then
  PERM=$(stat -c "%a" "$HOSTS_EQUIV" 2>/dev/null || stat -f "%Lp" "$HOSTS_EQUIV")
  OWNER=$(stat -c "%U:%G" "$HOSTS_EQUIV" 2>/dev/null || stat -f "%Su:%Sg" "$HOSTS_EQUIV")

  DETAILS+="Ownership and permissions validation:
Owner: $OWNER
Permissions: $PERM

"

  if [ "$OWNER" != "root:root" ] || [ "$PERM" -gt 600 ]; then
    STATUS="FAIL"
    REM="Set ownership to root:root and permissions to 600 on /etc/hosts.equiv"
  fi
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Trusted host access is securely configured or not in use"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="Trusted host configuration requires review"
else
  SUMMARY="Insecure trusted host configuration detected"
fi
OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 4: Listening ports
# -------------------------
CHECK="Listening Network Ports"
EXPECTED="No service should listen on port 21 (FTP) or 23 (Telnet)"
CMD="ss -tuln"
run_cmd "$CMD"
OUT="$CMD_OUT"

if echo "$OUT" | grep -Eq ":21\b|:21 |:23\b|:23 "; then
  STATUS="FAIL"
  REM="Disable FTP/Telnet services if not required; remove packages if possible"
  SUMMARY="Insecure ports detected (21 or 23 present)"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No insecure ports detected"
fi

OBS="$SUMMARY

Command executed:
$CMD

Full output:
$OUT"
add_audit_row "$CHECK" "$EXPECTED" "$OBS\n$OUT" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 5: Remote Trusted Services (rlogin, rsh, rexec)
# ----------------------------------------------------------
CHECK="Remote Trusted Services (rlogin, rsh, rexec)"
EXPECTED="Remote trusted services must be disabled or strictly restricted"

SUMMARY=""
DETAILS=""
STATUS="PASS"
REM="None"

# Step 1: chkconfig (RHEL only)
if command -v chkconfig >/dev/null 2>&1; then
  CMD="chkconfig --list | grep -E 'rlogin|rsh|rexec' || true"
  run_cmd "$CMD"
  CHK_OUT="$CMD_OUT"

  if [ -n "$CHK_OUT" ]; then
    DETAILS+="chkconfig output:\n$CHK_OUT\n\n"
    STATUS="REVIEW"
  else
    DETAILS+="chkconfig output:\n<none>\n\n"
  fi
fi

# Step 2: xinetd service definitions
CMD="ls -1 /etc/xinetd.d 2>/dev/null | grep -E 'rlogin|rsh|rexec' || true"
run_cmd "$CMD"
XINET_FILES="$CMD_OUT"

if [ -n "$XINET_FILES" ]; then
  STATUS="REVIEW"
  DETAILS+="xinetd service files:\n$XINET_FILES\n\n"

  for f in $XINET_FILES; do
    FILE="/etc/xinetd.d/$f"
    DISABLE_VAL=$(grep -Ei '^\s*disable\s*=' "$FILE" | awk -F= '{print $2}' | tr -d ' ')
    ONLY_FROM=$(grep -Ei '^\s*only_from' "$FILE")
    NO_ACCESS=$(grep -Ei '^\s*no_access' "$FILE")

    DETAILS+="File: $FILE\n"
    DETAILS+="disable = ${DISABLE_VAL:-not set}\n"
    DETAILS+="only_from = ${ONLY_FROM:-not set}\n"
    DETAILS+="no_access = ${NO_ACCESS:-not set}\n\n"

    if [ "$DISABLE_VAL" != "yes" ]; then
      STATUS="FAIL"
      REM="Disable r-services or restrict access using only_from/no_access"
    fi
  done
else
  DETAILS+="xinetd service files:\n<none>\n\n"
fi

# Step 3: .netrc files
CMD="find /home /root -xdev -type f -name .netrc -exec ls -l {} \; 2>/dev/null"
run_cmd "$CMD"
NETRC_OUT="$CMD_OUT"

if [ -n "$NETRC_OUT" ]; then
  STATUS="REVIEW"
  DETAILS+=".netrc files found:\n$NETRC_OUT\n\n"
  REM="Ensure .netrc files are empty, owned by root, and permission 000"
else
  DETAILS+=".netrc files found:\n<none>\n\n"
fi

# Step 4: .rhosts files
CMD="find /home /root -xdev -type f -name .rhosts -exec ls -l {} \; 2>/dev/null"
run_cmd "$CMD"
RHOSTS_OUT="$CMD_OUT"

if [ -n "$RHOSTS_OUT" ]; then
  STATUS="REVIEW"
  DETAILS+=".rhosts files found:\n$RHOSTS_OUT\n"
  REM="Ensure .rhosts files are empty, owned by root, and permission 000"
else
  DETAILS+=".rhosts files found:\n<none>\n"
fi

# Final summary
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="No remote trusted services enabled"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="Remote trusted service configuration present – review required"
else
  SUMMARY="Remote trusted services enabled or improperly restricted"
fi

OBS="$SUMMARY

Details:
$DETAILS"

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 6: Telnet
# -------------------------
CHECK="Telnet Service"
EXPECTED="No telnetd process and no listener on port 23"
CMD1="ps aux | grep -Ei 'telnetd|in.telnetd' | grep -v grep"
CMD2="ss -tuln"

run_cmd "$CMD1"
PROC_OUT="$CMD_OUT"
run_cmd "$CMD2"
SS_ALL="$CMD_OUT"
# filter for port 23 presence
PORT23="$(printf '%s\n' "$SS_ALL" | grep -E ':23\b|:23 ' || true)"

if [ -n "$PROC_OUT" ] || [ -n "$PORT23" ]; then
  STATUS="FAIL"
  REM="Stop and disable telnet, remove telnet packages (telnet-server/telnetd)"
  SUMMARY="Telnet process or listener detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No telnet processes or listeners detected"
fi

OBS="$SUMMARY

Commands executed:
$CMD1
$CMD2

Process output:
${PROC_OUT:-<none>}

ss -tuln (filtered):
${PORT23:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS/PROC_OUT" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 7: RSH
# -------------------------
CHECK="RSH Service"
EXPECTED="No rshd process and no listener on port 514"
CMD1="ps aux | grep -Ei 'rshd|in.rshd' | grep -v grep"
CMD2="ss -tuln"
run_cmd "$CMD1"
RSH_PROC_OUT="$CMD_OUT"
run_cmd "$CMD2"
SS_ALL="$CMD_OUT"
PORT514="$(printf '%s\n' "$SS_ALL" | grep -E ':514\b|:514 ' || true)"

if [ -n "$RSH_PROC_OUT" ] || [ -n "$PORT514" ]; then
  STATUS="FAIL"
  REM="Stop/remove rsh service and packages (rsh-server)"
  SUMMARY="RSH process or listener detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No RSH processes or listeners"
fi

OBS="$SUMMARY

Commands executed:
$CMD1
$CMD2

Process output:
${RSH_PROC_OUT:-<none>}

ss -tuln (filtered):
${PORT514:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 8: FTP
# -------------------------
CHECK="FTP Service"
EXPECTED="No FTP daemon (vsftpd/proftpd/pure-ftpd) and no listener on port 21"
CMD1="ps aux | grep -Ei 'vsftpd|proftpd|pure-ftpd' | grep -v grep"
CMD2="ss -tuln"
run_cmd "$CMD1"
FTP_PROC_OUT="$CMD_OUT"
run_cmd "$CMD2"
SS_ALL="$CMD_OUT"
PORT21="$(printf '%s\n' "$SS_ALL" | grep -E ':21\b|:21 ' || true)"

if [ -n "$FTP_PROC_OUT" ] || [ -n "$PORT21" ]; then
  STATUS="FAIL"
  REM="Disable FTP daemons and migrate to SFTP"
  SUMMARY="FTP service/port detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No FTP service detected"
fi

OBS="$SUMMARY

Commands executed:
$CMD1
$CMD2

Process output:
${FTP_PROC_OUT:-<none>}

ss -tuln (filtered):
${PORT21:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 9: Anonymous Login to FTP
# ----------------------------------------------------------
CHECK="Anonymous Login to FTP"
EXPECTED="Anonymous FTP login must be disabled and FTP access must be restricted"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- ss -tuln
- cat /etc/vsftpd/vsftpd.conf
- cat /etc/vsftpd/user_list
- cat /etc/vsftpd/ftpusers"

# -------------------------
# FTP port listening check
# -------------------------
CMD="ss -tuln | grep -E ':21\\b|:21 ' || true"
run_cmd "$CMD"
FTP_PORT_OUT="$CMD_OUT"

if [ -n "$FTP_PORT_OUT" ]; then
  DETAILS+="FTP port 21 is listening:
$FTP_PORT_OUT

"
else
  DETAILS+="FTP port 21 is not listening

"
fi

# -------------------------
# vsftpd configuration
# -------------------------
VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"

if [ -f "$VSFTPD_CONF" ]; then
  ANON_ENABLE=$(grep -Ei '^anonymous_enable' "$VSFTPD_CONF" | awk -F= '{print $2}' | tr -d ' ')
  USERLIST_ENABLE=$(grep -Ei '^userlist_enable' "$VSFTPD_CONF" | awk -F= '{print $2}' | tr -d ' ')
  USERLIST_DENY=$(grep -Ei '^userlist_deny' "$VSFTPD_CONF" | awk -F= '{print $2}' | tr -d ' ')

  DETAILS+="vsftpd configuration:
anonymous_enable = ${ANON_ENABLE:-not set}
userlist_enable = ${USERLIST_ENABLE:-not set}
userlist_deny = ${USERLIST_DENY:-not set}

"

  if [ "$ANON_ENABLE" = "YES" ]; then
    STATUS="FAIL"
    REM="Set anonymous_enable=NO in /etc/vsftpd/vsftpd.conf and restart vsftpd"
  fi
else
  DETAILS+="vsftpd configuration file not found

"
fi

# -------------------------
# user_list file
# -------------------------
if [ -f /etc/vsftpd/user_list ]; then
  CMD="cat /etc/vsftpd/user_list"
  run_cmd "$CMD"
  DETAILS+="user_list file:
$CMD_OUT

"
else
  DETAILS+="user_list file not found

"
fi

# -------------------------
# ftpusers file
# -------------------------
if [ -f /etc/vsftpd/ftpusers ]; then
  CMD="cat /etc/vsftpd/ftpusers"
  run_cmd "$CMD"
  DETAILS+="ftpusers file:
$CMD_OUT

"
else
  DETAILS+="ftpusers file not found

"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Anonymous FTP login is disabled and FTP access is properly restricted"
else
  SUMMARY="Anonymous FTP login is enabled or FTP configuration is insecure"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 10: Restricted Users and FTP Access Control
# ----------------------------------------------------------
CHECK="Restricted Users and FTP Access Control"
EXPECTED="Restricted system users must not have login shells and must be denied FTP access"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- cat /etc/ftpusers
- cat /etc/vsftpd/ftpusers
- cat /etc/vsftpd.user_list"

# -------------------------
# Step 1: Identify restricted users from /etc/passwd
# -------------------------
CMD="awk -F: '{print \$1 \":\" \$7}' /etc/passwd"
run_cmd "$CMD"
PASSWD_SHELLS="$CMD_OUT"
RESTRICTED_USERS=$(echo "$PASSWD_SHELLS" | grep -Ev '(/bin/bash|/bin/sh|/bin/ksh|/bin/zsh|/bin/csh)$' || true)

DETAILS+="Restricted users based on shell (/etc/passwd user:shell):
${RESTRICTED_USERS:-<none>}

"

# -------------------------
# Step 2: Verify restricted users do not have login shells
# -------------------------
LOGIN_SHELL_USERS=$(echo "$RESTRICTED_USERS" | grep -E '(/bin/bash|/bin/sh|/bin/ksh|/bin/zsh|/bin/csh)' || true)

if [ -n "$LOGIN_SHELL_USERS" ]; then
  STATUS="FAIL"
  REM="Ensure restricted users use nologin or false shells"
  DETAILS+="Restricted users with login shells detected:
$LOGIN_SHELL_USERS

"
fi

# -------------------------
# Step 3: FTP users restriction files
# -------------------------
FTP_DENY_LIST=""

if [ -f /etc/ftpusers ]; then
  CMD="cat /etc/ftpusers"
  run_cmd "$CMD"
  FTP_DENY_LIST+="/etc/ftpusers:
$CMD_OUT

"
fi

if [ -f /etc/vsftpd/ftpusers ]; then
  CMD="cat /etc/vsftpd/ftpusers"
  run_cmd "$CMD"
  FTP_DENY_LIST+="/etc/vsftpd/ftpusers:
$CMD_OUT

"
fi

if [ -f /etc/vsftpd.user_list ]; then
  CMD="cat /etc/vsftpd.user_list"
  run_cmd "$CMD"
  FTP_DENY_LIST+="/etc/vsftpd.user_list:
$CMD_OUT

"
fi

DETAILS+="FTP restricted user lists:
${FTP_DENY_LIST:-<no ftp restriction files found>}

"

# -------------------------
# Step 4: Verify restricted users are denied FTP
# -------------------------
FTP_MISSING=""
for user in $(echo "$RESTRICTED_USERS" | cut -d: -f1); do
  echo "$FTP_DENY_LIST" | grep -qw "$user" || FTP_MISSING+="$user "
done

if [ -n "$FTP_MISSING" ]; then
  STATUS="REVIEW"
  REM="Ensure restricted users are added to FTP deny lists"
  DETAILS+="Restricted users missing from FTP deny lists:
$FTP_MISSING

"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Restricted users do not have login shells and are denied FTP access"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="Restricted users detected that require FTP access review"
else
  SUMMARY="Restricted users with login shells or FTP access detected"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 11: SSH Service Status
# ----------------------------------------------------------
CHECK="SSH Service Status"
EXPECTED="SSH service should be active (running) and enabled at boot"
SERVICE_UNIT=""
SERVICE_ACTIVE=""
SERVICE_ENABLED=""

UNIT_LINE=$(systemctl list-unit-files | grep -E '^ssh(d)?\.service' | head -n 1)

if echo "$UNIT_LINE" | grep -q '^sshd.service'; then
  SERVICE_UNIT="sshd"
elif echo "$UNIT_LINE" | grep -q '^ssh.service'; then
  SERVICE_UNIT="ssh"
else
  SERVICE_UNIT=""
fi

if [ -z "$SERVICE_UNIT" ]; then
  STATUS="FAIL"
  REM="Install OpenSSH server package"
  SUMMARY="SSH service not installed"
  SERVICE_ACTIVE="not installed"
  SERVICE_ENABLED="not installed"
else
  run_cmd "systemctl is-active $SERVICE_UNIT"
  SERVICE_ACTIVE="$CMD_OUT"

  run_cmd "systemctl is-enabled $SERVICE_UNIT"
  SERVICE_ENABLED="$CMD_OUT"

  if [ "$SERVICE_ACTIVE" = "active" ] && [ "$SERVICE_ENABLED" = "enabled" ]; then
    STATUS="PASS"
    REM="None"
    SUMMARY="SSH service is active and enabled"
  else
    STATUS="FAIL"
    REM="Start and enable SSH service: systemctl enable --now $SERVICE_UNIT"
    SUMMARY="SSH service is installed but not active and enabled"
  fi
fi

# --------------------------------------------------
# Observation
# --------------------------------------------------
OBS="$SUMMARY

Detected unit file:
${UNIT_LINE:-<none>}

SSH service unit:
${SERVICE_UNIT:-<none>}

Service active status:
$SERVICE_ACTIVE

Service enabled status:
$SERVICE_ENABLED"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 12: PermitRootLogin
# -------------------------
CHECK="PermitRootLogin"
EXPECTED="PermitRootLogin in /etc/ssh/sshd_config should be 'no'"
CMD="grep -E "^#?PermitRootLogin" /etc/ssh/sshd_config || true"
run_cmd "$CMD"
PRL_OUT="$CMD_OUT"

if echo "$PRL_OUT" | grep -qi "no"; then
  STATUS="PASS"; REM="None"; SUMMARY="PermitRootLogin = no"
else
  STATUS="FAIL"; REM="Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd"; SUMMARY="PermitRootLogin not set to no"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
${PRL_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 13: Trust files
# -------------------------
CHECK="Trust Files (.rhosts .shosts hosts.equiv)"
EXPECTED="No trust files should exist under / (maxdepth 5)"
CMD="find / -name '.rhosts' -o -name '.shosts' -o -name 'hosts.equiv' 2>/dev/null || true"
run_cmd "$CMD"
FILES_OUT="$CMD_OUT"

if [ -n "$FILES_OUT" ]; then
  STATUS="FAIL"; REM="Remove trust files immediately"; SUMMARY="Trust files present"
else
  STATUS="PASS"; REM="None"; SUMMARY="No trust files found"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
${FILES_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 14: /etc/shadow permissions
# -------------------------
CHECK="/etc/shadow File Permissions"
EXPECTED="/etc/shadow should be owned by root:shadow with permission 640"
CMD="ls -l /etc/shadow"

run_cmd "$CMD"
SHADOW_PERM="$CMD_OUT"

PERM=$(stat -c "%a" /etc/shadow 2>/dev/null || stat -f "%Lp" /etc/shadow)
OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null || stat -f "%Su:%Sg" /etc/shadow)

if [ "$PERM" = "640" ] && [ "$OWNER" = "root:shadow" ]; then
  STATUS="PASS"
  REM="None"
  SUMMARY="Correct permissions and ownership on /etc/shadow"
else
  STATUS="FAIL"
  REM="Run: chown root:shadow /etc/shadow && chmod 640 /etc/shadow"
  SUMMARY="Incorrect permissions or ownership on /etc/shadow"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
$SHADOW_PERM

Detected:
Permissions: $PERM
Owner: $OWNER"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 15: Password aging policy (users)
# -------------------------
CHECK="Password Aging Policy"
EXPECTED="Maximum password age should be defined (≤ 90 days recommended)"
AGING_ISSUES=""
DETAILS=""

for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  run_cmd "chage -l $user"
  OUT="$CMD_OUT"
  MAX_DAYS=$(echo "$OUT" | awk -F: '/Maximum/ {gsub(/ /,"",$2); print $2}')

  DETAILS+="User: $user
$OUT

"

  if [ -z "$MAX_DAYS" ] || [ "$MAX_DAYS" = "99999" ]; then
    AGING_ISSUES+="User $user has no effective password expiry\n"
  fi
done

if [ -n "$AGING_ISSUES" ]; then
  STATUS="FAIL"
  REM="Set password aging using: chage -M 90 -m 7 -W 14 <username>"
  SUMMARY="Password aging not enforced for one or more users"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="Password aging policy enforced for all users"
fi

OBS="$SUMMARY

Details:
$DETAILS

Issues:
${AGING_ISSUES:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 16: Monitoring of User Access and New User Validation
# ----------------------------------------------------------
CHECK="Monitoring of User Access and New User Validation"
EXPECTED="User account creation and modifications must be monitored, approved, and aligned with job roles as per policy"
STATUS="REVIEW"
REM="Review new or modified user accounts for approval evidence, role alignment, and access monitoring controls"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- ls -l /etc/passwd
- stat /etc/passwd"

# -------------------------
# STEP 1: Capture current user accounts
# -------------------------
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

DETAILS+="Current user accounts (/etc/passwd):
$PASSWD_OUT

"

# -------------------------
# STEP 2: Capture passwd file metadata
# -------------------------
CMD="ls -l /etc/passwd"
run_cmd "$CMD"
PASSWD_META="$CMD_OUT"

DETAILS+="/etc/passwd file metadata:
$PASSWD_META

"

# -------------------------
# STEP 3: Capture last modification timestamp
# -------------------------
PASSWD_MTIME=$(stat -c '%y' /etc/passwd 2>/dev/null || stat -f '%Sm' /etc/passwd)

DETAILS+="/etc/passwd last modified timestamp:
$PASSWD_MTIME

"

# -------------------------
# STEP 4: Identify non-system users (UID >= 1000)
# -------------------------
CMD="awk -F: '\$3 >= 1000 {print \$1 \":UID=\" \$3 \":HOME=\" \$6 \":SHELL=\" \$7}' /etc/passwd"
run_cmd "$CMD"
NON_SYSTEM_USERS="$CMD_OUT"

DETAILS+="Non-system user accounts (UID >= 1000):
${NON_SYSTEM_USERS:-<none>}

"

# -------------------------
# Audit interpretation
# -------------------------
SUMMARY="User account information has been collected for monitoring and validation.
Accounts created or modified during the audit period must be identified by comparing this output with prior audit baselines.
A sample of new or changed accounts should be reviewed for documented approval, appropriate access provisioning, and monitoring controls."

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 17: User Group Membership Review
# ----------------------------------------------------------
CHECK="User Group Membership Review"
EXPECTED="Only authorized administrators may belong to sensitive system groups"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/group
- cat /etc/passwd"

# -------------------------
# Capture group file
# -------------------------
CMD="cat /etc/group"
run_cmd "$CMD"
GROUP_OUT="$CMD_OUT"

DETAILS+="System groups (/etc/group):
$GROUP_OUT

"

# -------------------------
# Capture passwd file
# -------------------------
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

DETAILS+="System users (/etc/passwd):
$PASSWD_OUT

"

# -------------------------
# Map users to primary groups
# -------------------------
USER_PRIMARY_GROUPS=$(awk -F: 'NR==FNR {gid[$3]=$1; next} {print $1 ":" gid[$4]}' /etc/group /etc/passwd)

DETAILS+="User to primary group mapping (user:primary_group):
$USER_PRIMARY_GROUPS

"

# -------------------------
# Identify secondary group memberships
# -------------------------
SECONDARY_GROUPS=$(awk -F: 'NF==4 && $4!="" {print $1 ":" $4}' /etc/group)

DETAILS+="Secondary group memberships (group:users):
${SECONDARY_GROUPS:-<none>}

"

# -------------------------
# Sensitive group enforcement
# -------------------------
SENSITIVE_GROUPS="root bin sys adm daemon mail lp tty uucp users smbnull cdwrite nogroup"

UNAUTHORIZED_MEMBERS=""
for grp in $SENSITIVE_GROUPS; do
  MEMBERS=$(echo "$SECONDARY_GROUPS" | awk -F: -v g="$grp" '$1==g {print $2}')
  if [ -n "$MEMBERS" ]; then
    UNAUTHORIZED_MEMBERS+="$grp:$MEMBERS"$'\n'
  fi
done

if [ -n "$UNAUTHORIZED_MEMBERS" ]; then
  STATUS="FAIL"
  REM="Remove non-administrative users from sensitive system groups"
  DETAILS+="Unauthorized sensitive group memberships detected:
$UNAUTHORIZED_MEMBERS

"
else
  DETAILS+="No unauthorized sensitive group memberships detected

"
fi

# -------------------------
# Observation
# -------------------------
SUMMARY="User group membership validation completed"

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"


# -------------------------
# CHECK 18: System startup script permissions
# -------------------------
CHECK="System Startup Script Permissions"
EXPECTED="Startup scripts must be owned by root and not writable by group/others"
ISSUES=""

# /etc/init.d (SysV – RHEL & Ubuntu)
if [ -d /etc/init.d ]; then
  while IFS= read -r file; do
    perm=$(stat -c "%a" "$file" 2>/dev/null)
    owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
    if [ "${perm:1:1}" -ge 2 ] || [ "${perm:2:1}" -ge 2 ] || [ "$owner" != "root:root" ]; then
      ISSUES+="$file ($perm $owner)\n"
    fi
  done < <(find /etc/init.d -type f 2>/dev/null)
fi

# /etc/systemd/system (systemd – RHEL & Ubuntu)
if [ -d /etc/systemd/system ]; then
  while IFS= read -r file; do
    perm=$(stat -c "%a" "$file" 2>/dev/null)
    owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
    if [ "${perm:1:1}" -ge 2 ] || [ "${perm:2:1}" -ge 2 ] || [ "$owner" != "root:root" ]; then
      ISSUES+="$file ($perm $owner)\n"
    fi
  done < <(find /etc/systemd/system -type f 2>/dev/null)
fi

if [ -n "$ISSUES" ]; then
  STATUS="FAIL"
  REM="Set ownership to root:root and permissions to 644"
  SUMMARY="Insecure startup file permissions detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="Startup file permissions are secure"
fi

OBS="$SUMMARY

Issues:
${ISSUES:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 19: User shell startup files
# -------------------------
CHECK="User Shell Startup File Permissions"
EXPECTED="Shell startup files should be 644 or stricter and owned by user"
ISSUES=""
FILES_CHECKED=""

while IFS=: read -r user _ uid _ _ home _; do
  [ "$uid" -lt 1000 ] && continue
  for f in .bashrc .bash_profile .profile; do
    file="$home/$f"
    if [ -f "$file" ]; then
      FILES_CHECKED+="$file\n"
      perm=$(stat -c "%a" "$file" 2>/dev/null)
      owner=$(stat -c "%U" "$file" 2>/dev/null)
      if [ "$perm" -gt 644 ] || [ "$owner" != "$user" ]; then
        ISSUES+="$file ($perm owner=$owner)\n"
      fi
    fi
  done
done < /etc/passwd

if [ -n "$ISSUES" ]; then
  STATUS="FAIL"
  REM="Restrict permissions: chmod 644 and ensure correct ownership"
  SUMMARY="Insecure user shell startup files detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="User shell startup files are secure"
fi

OBS="$SUMMARY

Files checked:
${FILES_CHECKED:-<none>}

Issues:
${ISSUES:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 20: Current session umask
# -------------------------
CHECK="Current Session Umask"
EXPECTED="Umask should be 027 or stricter (avoid 002 or 022)"
CMD="umask"
run_cmd "$CMD"
SESSION_UMASK="$CMD_OUT"
UMASK_NUM=$(printf "%03d" "$SESSION_UMASK" 2>/dev/null)

if [ "$UMASK_NUM" -le 027 ]; then
  STATUS="PASS"
  REM="None"
  SUMMARY="Secure session umask detected ($UMASK_NUM)"
else
  STATUS="FAIL"
  REM="Set umask 027 in global shell configuration"
  SUMMARY="Weak session umask detected ($UMASK_NUM)"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
$SESSION_UMASK"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 21: System-wide default umask (/etc/login.defs)
# -------------------------
CHECK="System-wide Default Umask"
EXPECTED="UMASK in /etc/login.defs should be set to 027"
CMD="grep -E '^UMASK' /etc/login.defs 2>/dev/null || true"
run_cmd "$CMD"
LOGIN_DEFS_UMASK="$CMD_OUT"

if echo "$LOGIN_DEFS_UMASK" | grep -q "027"; then
  STATUS="PASS"
  REM="None"
  SUMMARY="Secure default umask configured in /etc/login.defs"
else
  STATUS="FAIL"
  REM="Set UMASK 027 in /etc/login.defs"
  SUMMARY="Default umask not set to 027 in /etc/login.defs"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
${LOGIN_DEFS_UMASK:-<not set>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 22: Umask overrides in shell configuration
# -------------------------
CHECK="Global Umask Overrides"
EXPECTED="Shell config files should not override umask with weak values"
CMD1="grep -R \"umask\" /etc/profile /etc/bashrc 2>/dev/null || true"
run_cmd "$CMD1"
SHELL_UMASKS="$CMD_OUT"

WEAK_OVERRIDE=$(echo "$SHELL_UMASKS" | grep -E "umask[[:space:]]+(002|022)" || true)

if [ -n "$WEAK_OVERRIDE" ]; then
  STATUS="FAIL"
  REM="Replace weak umask values with umask 027 in shell configuration files"
  SUMMARY="Weak umask override detected in shell configuration"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No weak umask overrides found"
fi

OBS="$SUMMARY

Files checked:
/etc/profile
/etc/bashrc

Detected umask entries:
${SHELL_UMASKS:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# -------------------------
# CHECK 23: Skeleton directory permissions (/etc/skel)
# -------------------------
CHECK="Skeleton Directory Permissions"
EXPECTED="Files in /etc/skel should not be world-writable"
CMD="ls -l /etc/skel 2>/dev/null || true"
run_cmd "$CMD"
SKEL_OUT="$CMD_OUT"

WORLD_WRITABLE=$(ls -l /etc/skel 2>/dev/null | awk '$1 ~ /w.$/ {print}')

if [ -n "$WORLD_WRITABLE" ]; then
  STATUS="FAIL"
  REM="Remove world-writable permissions from /etc/skel files"
  SUMMARY="World-writable files found in /etc/skel"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="Skeleton directory permissions are secure"
fi

OBS="$SUMMARY

Command executed:
$CMD

World-writable files:
${WORLD_WRITABLE:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 24: SUID and SGID binaries
# ----------------------------------------------------------
CHECK="SUID and SGID Binaries"
EXPECTED="Only required binaries should have SUID/SGID permissions"
CMD="find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null"
run_cmd "$CMD"
SUID_OUT="$CMD_OUT"

if [ -n "$SUID_OUT" ]; then
  STATUS="REVIEW"
  REM="Review the list and remove unnecessary SUID/SGID permissions"
  SUMMARY="SUID/SGID binaries detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No SUID/SGID binaries found"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
${SUID_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 25: sudo and wheel group members
# ----------------------------------------------------------
CHECK="sudo and wheel Group Membership"
EXPECTED="Only authorized administrators should belong to sudo or wheel groups"
SUDO_GRP="$(grep '^sudo:' /etc/group 2>/dev/null || true)"
WHEEL_GRP="$(grep '^wheel:' /etc/group 2>/dev/null || true)"

OBS="sudo group:
${SUDO_GRP:-<not present>}

wheel group:
${WHEEL_GRP:-<not present>}"

STATUS="REVIEW"
REM="Verify that only authorized administrators are members"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 26: Multiple UID 0 accounts
# ----------------------------------------------------------
CHECK="Multiple UID 0 Accounts"
EXPECTED="Only the root account should have UID 0"
CMD="awk -F: '\$3 == 0 { print \$1 }' /etc/passwd"
run_cmd "$CMD"
UID0_OUT="$CMD_OUT"
UID0_COUNT=$(echo "$UID0_OUT" | wc -l)

if [ "$UID0_COUNT" -gt 1 ]; then
  STATUS="FAIL"
  REM="Remove UID 0 from non-root accounts"
  SUMMARY="Multiple UID 0 accounts detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="Only root has UID 0"
fi

OBS="$SUMMARY

Command executed:
$CMD

Accounts with UID 0:
$UID0_OUT"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 27: Locate world-readable dump / export files
# ----------------------------------------------------------
CHECK="Dump / Export Files Presence"
EXPECTED="Dump/export files must be owned by oracle and must not be world-readable"
CMD='find / -type f \( -name "*.dmp" -o -name "*.sql" -o -name "*.exp" -o -name "*.csv" \) \
-perm -0004 ! -user oracle -exec ls -l {} \; 2>/dev/null'
run_cmd "$CMD"
DUMP_FILES_OUT="$CMD_OUT"

if [ -n "$DUMP_FILES_OUT" ]; then
  STATUS="REVIEW"
  REM="Change ownership to oracle and remove world-read permission (chown oracle:oracle, chmod 600)"
  SUMMARY="World-readable dump/export files found not owned by oracle"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No world-readable dump/export files found"
fi

OBS="$SUMMARY

Criteria:
- File extensions: .dmp .sql .exp .csv
- World-readable files
- Not owned by oracle

Command executed:
$CMD

Output:
${DUMP_FILES_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 28: Dump files in insecure locations (/tmp, /var/tmp)
# ----------------------------------------------------------
CHECK="Dump Files in Insecure Locations"
EXPECTED="No dump/export files should exist in /tmp or /var/tmp"
CMD="find /tmp /var/tmp -type f \( -name \"*.dmp\" -o -name \"*.sql\" -o -name \"*.exp\" \) 2>/dev/null"
run_cmd "$CMD"
TMP_DUMP_OUT="$CMD_OUT"

if [ -n "$TMP_DUMP_OUT" ]; then
  STATUS="FAIL"
  REM="Move dump files to secure directory and restrict permissions"
  SUMMARY="Dump files detected in insecure temporary directories"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="No dump files found in /tmp or /var/tmp"
fi

OBS="$SUMMARY

Command executed:
$CMD

Output:
${TMP_DUMP_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 29: Dump directory permissions and ownership
# ----------------------------------------------------------
DUMP_DIR="/u01/dumpfiles"
CHECK="Dump Directory Permissions and Ownership"
EXPECTED="Dump directory should be owned by DB user and permission should be 700"
CMD="ls -ld $DUMP_DIR 2>/dev/null"
run_cmd "$CMD"
DUMP_DIR_LS="$CMD_OUT"

if [ -d "$DUMP_DIR" ]; then
  PERM=$(stat -c "%a" "$DUMP_DIR" 2>/dev/null || stat -f "%Lp" "$DUMP_DIR")
  OWNER=$(stat -c "%U:%G" "$DUMP_DIR" 2>/dev/null || stat -f "%Su:%Sg" "$DUMP_DIR")

  if [ "$PERM" -le 700 ]; then
    STATUS="PASS"
    REM="None"
    SUMMARY="Dump directory permissions are restricted"
  else
    STATUS="FAIL"
    REM="Run: chmod 700 $DUMP_DIR"
    SUMMARY="Dump directory permissions are too open"
  fi

  OBS="$SUMMARY

Command executed:
$CMD

ls output:
$DUMP_DIR_LS

Detected:
Permissions: $PERM
Owner: $OWNER"
else
  STATUS="REVIEW"
  REM="Ensure dump directory is created securely"
  SUMMARY="Dump directory not found"

  OBS="$SUMMARY

Command executed:
$CMD

Result:
Directory does not exist"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 30: Encrypted exports usage
# ----------------------------------------------------------
CHECK="Encrypted Exports"
EXPECTED="Exports should use encryption (ENCRYPTION=ALL or equivalent)"
CMD="find /u01 /opt /home /etc -type f \( -name "*.sh" -o -name "*.par" \) -exec grep -H "expdp" {} \; 2>/dev/null | grep -vi "ENCRYPTION=ALL" "
run_cmd "$CMD"
ENCRYPT_OUT="$CMD_OUT"



if [ -n "$ENCRYPT_OUT" ]; then
  STATUS="FAIL"
  REM="Ensure ENCRYPTION=ALL is specified in all expdp export scripts"
  SUMMARY="Unencrypted database exports detected"
else
  STATUS="PASS"
  REM="None"
  SUMMARY="All detected export scripts use encryption"
fi

OBS="$SUMMARY

Command executed:
$CMD

Sample output:
${ENCRYPT_OUT:-<none>}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 31: Audit logs for dump file access
# ----------------------------------------------------------
CHECK="File Copy / Move / Delete Activity Logging"
EXPECTED="File operations should be logged via auditd. If auditd is unavailable, alternative logs must be reviewed."
TARGET_DIR="/u01/dumpfiles"

if command -v ausearch >/dev/null 2>&1 && [ -f /var/log/audit/audit.log ]; then
  # auditd available
  CMD="ausearch -f $TARGET_DIR -ts today 2>/dev/null | head -n 20"
  run_cmd "$CMD"
  AUDIT_OUT="$CMD_OUT"

  STATUS="PASS"
  REM="None"
  SUMMARY="auditd is enabled; file activity is logged in audit logs"

  OBS="$SUMMARY

Audit log location:
/var/log/audit/audit.log

Command executed:
$CMD

Sample audit entries:
${AUDIT_OUT:-<no recent activity>}"

else
  # auditd not available – fallback
  CMD1="grep -R \"$TARGET_DIR\" /var/log 2>/dev/null | head -n 10"
  CMD2="journalctl 2>/dev/null | grep \"$TARGET_DIR\" | head -n 10"

  run_cmd "$CMD1"
  SYSLOG_OUT="$CMD_OUT"

  run_cmd "$CMD2"
  JOURNAL_OUT="$CMD_OUT"

  STATUS="REVIEW"
  REM="Install and enable auditd and configure file watch rules for full auditing"
  SUMMARY="auditd not installed or not enabled; alternative logs reviewed"

  OBS="$SUMMARY

auditd status:
Not installed or not enabled

Fallback review performed using:
- /var/log system logs
- journalctl

System log findings:
${SYSLOG_OUT:-<none>}

Journalctl findings:
${JOURNAL_OUT:-<none>}"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 32: Secure deletion guidance
# ----------------------------------------------------------
CHECK="Secure Deletion of Dump Files"
EXPECTED="Sensitive dump files should be securely deleted (shred/srm)"
STATUS="REVIEW"
REM="Use: shred -u <sensitive_dump_file>.dmp"
SUMMARY="Secure deletion should be used for sensitive dump files"
OBS="$SUMMARY
Recommended (not executed):
shred -u <sensitive_dump_file>.dmp"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"


# ----------------------------------------------------------
# CHECK 33: auditd rule for dump file monitoring
# ----------------------------------------------------------
CHECK="Auditd Rule for Dump File Monitoring"
EXPECTED="Audit rules should monitor creation and access of dump files"
STATUS="REVIEW"
REM="Add rule: auditctl -w $DUMP_DIR -p rwxa -k dump_access"
SUMMARY="Auditd rule should be configured for dump file access"

OBS="$SUMMARY
Recommended rule (not applied):
auditctl -w $DUMP_DIR -p rwxa -k dump_access"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 34: Root Home Directory Files & Permissions
# ----------------------------------------------------------
CHECK="Root Home Directory Files & Permissions"
EXPECTED="Root home directory files must have secure permissions (400 or 600) and root home must not be accessible to non-root users"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- ls -al /root/
- ls -al /"
CMD="ls -al /root/ 2>&1 || true"
run_cmd "$CMD"
ROOT_DIR_OUT="$CMD_OUT"

if echo "$ROOT_DIR_OUT" | grep -qi "Permission denied"; then
  DETAILS+="Root home directory listing (/root):
Access denied for non-root user (expected and secure)

"
elif [ -n "$ROOT_DIR_OUT" ]; then
  DETAILS+="Root home directory listing (/root):
$ROOT_DIR_OUT

"
else
  DETAILS+="Root home directory listing (/root):
<no output>

"
fi

INSECURE_FILES=""

for file in .bashrc .bash_profile .bash_logout .cshrc .login .profile .kshrc .emacs .exrc .forward .rhosts .dtprofile .Xdefaults; do
  FILE_PATH="/root/$file"
  if [ -f "$FILE_PATH" ]; then
    PERM=$(stat -c "%a" "$FILE_PATH" 2>/dev/null || stat -f "%Lp" "$FILE_PATH")
    OWNER=$(stat -c "%U:%G" "$FILE_PATH" 2>/dev/null || stat -f "%Su:%Sg" "$FILE_PATH")

    if [ "$OWNER" != "root:root" ] || [ "$PERM" -gt 600 ]; then
      INSECURE_FILES+="$FILE_PATH (perm=$PERM owner=$OWNER)
"
    fi
  fi
done

if [ -n "$INSECURE_FILES" ]; then
  STATUS="FAIL"
  REM="Set ownership to root:root and permissions to 400 or 600 on root startup files"
  DETAILS+="Insecure root startup files detected:
$INSECURE_FILES
"
else
  DETAILS+="All checked root startup files have secure permissions
"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Root home directory files and permissions are securely configured"
else
  SUMMARY="Insecure permissions or ownership detected in root home directory files"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 35: Umask Configuration
# ----------------------------------------------------------
CHECK="Umask Configuration"
EXPECTED="System-wide and user umask values should be secure (027 recommended, 022 acceptable, 077 only if justified)"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- grep umask /etc/bashrc or /etc/bash.bashrc
- grep umask /etc/profile
- grep -R umask /home"

# -------------------------
# Detect system bashrc file
# -------------------------
SYSTEM_BASHRC=""

if [ -f /etc/bashrc ]; then
  SYSTEM_BASHRC="/etc/bashrc"
elif [ -f /etc/bash.bashrc ]; then
  SYSTEM_BASHRC="/etc/bash.bashrc"
fi

# -------------------------
# System bashrc umask
# -------------------------
if [ -n "$SYSTEM_BASHRC" ]; then
  CMD="grep -E '^[^#]*umask' $SYSTEM_BASHRC || true"
  run_cmd "$CMD"
  BASHRC_UMASK="$CMD_OUT"

  DETAILS+="$SYSTEM_BASHRC umask entries:
${BASHRC_UMASK:-<none>}

"
else
  DETAILS+="System bashrc file not found

"
fi

# -------------------------
# /etc/profile umask
# -------------------------
CMD="grep -E '^[^#]*umask' /etc/profile 2>/dev/null || true"
run_cmd "$CMD"
PROFILE_UMASK="$CMD_OUT"
DETAILS+="/etc/profile umask entries:
${PROFILE_UMASK:-<none>}
"

CMD="grep -R '^[^#]*umask' /home 2>/dev/null || true"
run_cmd "$CMD"
USER_UMASK="$CMD_OUT"

DETAILS+="/home user umask entries:
${USER_UMASK:-<none>}
"

NON_STANDARD_UMASK=$(printf "%s\n%s\n%s\n" \
  "$BASHRC_UMASK" "$PROFILE_UMASK" "$USER_UMASK" \
  | grep -E 'umask[[:space:]]+(077)' || true)

if [ -n "$NON_STANDARD_UMASK" ]; then
  STATUS="REVIEW"
  REM="Review justification for umask 077; standard values are 027 or 022"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Umask values are configured appropriately at system and user levels"
else
  SUMMARY="Non-standard umask values detected; review required"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 36: Password Policy and Authentication Controls
# ----------------------------------------------------------
CHECK="Password Policy and Authentication Controls"
EXPECTED="Password aging, complexity, lockout, and history controls should align with security policy"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- grep PASS_* /etc/login.defs
- grep pam_pwquality /etc/pam.d/*
- grep pam_faillock /etc/pam.d/*
- grep remember= /etc/pam.d/*
- ls -l /etc/security/opasswd"

# --------------------------------------------------
# /etc/login.defs – password aging & warning
# --------------------------------------------------
if [ -f /etc/login.defs ]; then
  CMD="grep -E '^[[:space:]]*PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)' /etc/login.defs"
  run_cmd "$CMD"
  LOGIN_DEFS_OUT="$CMD_OUT"

  DETAILS+="/etc/login.defs settings:
${LOGIN_DEFS_OUT:-<none>}

"

  PASS_MAX_DAYS=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs 2>/dev/null | tail -1)
  PASS_MIN_DAYS=$(awk '$1=="PASS_MIN_DAYS"{print $2}' /etc/login.defs 2>/dev/null | tail -1)
  PASS_WARN_AGE=$(awk '$1=="PASS_WARN_AGE"{print $2}' /etc/login.defs 2>/dev/null | tail -1)

  if [[ "$PASS_MAX_DAYS" =~ ^[0-9]+$ ]] && [ "$PASS_MAX_DAYS" -gt 90 ]; then
    STATUS="REVIEW"
    REM="Password maximum age exceeds recommended value (90 days or less)"
  fi
else
  DETAILS+="/etc/login.defs file not found

"
fi

# --------------------------------------------------
# Password quality module (pwquality / cracklib)
# --------------------------------------------------
CMD="grep -R 'pam_pwquality.so\|pam_cracklib.so' /etc/pam.d 2>/dev/null"
run_cmd "$CMD"
PWQUALITY_OUT="$CMD_OUT"
DETAILS+="Password quality module configuration:
${PWQUALITY_OUT:-<not configured>}

"

if [ -z "$PWQUALITY_OUT" ]; then
  STATUS="REVIEW"
  REM="Password complexity enforcement is not configured"
fi

# --------------------------------------------------
# Account lockout (faillock)
# --------------------------------------------------
CMD="grep -R 'pam_faillock.so' /etc/pam.d 2>/dev/null"
run_cmd "$CMD"
FAILLOCK_OUT="$CMD_OUT"

if [ -n "$FAILLOCK_OUT" ]; then
  DETAILS+="Account lockout configuration:
$FAILLOCK_OUT

"
else
  STATUS="REVIEW"
  REM="Account lockout protection is not configured"
  DETAILS+="Account lockout (faillock) not configured

"
fi

# --------------------------------------------------
# Password history
# --------------------------------------------------
CMD="grep -R 'remember=' /etc/pam.d 2>/dev/null"
run_cmd "$CMD"
HISTORY_OUT="$CMD_OUT"
DETAILS+="Password history configuration:
${HISTORY_OUT:-<not configured>}

"

if [ -z "$HISTORY_OUT" ]; then
  STATUS="REVIEW"
  REM="Password history enforcement is not configured"
fi

# --------------------------------------------------
# opasswd file permissions
# --------------------------------------------------
if [ -f /etc/security/opasswd ]; then
  OPASSWD_PERM=$(stat -c "%a" /etc/security/opasswd 2>/dev/null || stat -f "%Lp" /etc/security/opasswd)
  OPASSWD_OWNER=$(stat -c "%U:%G" /etc/security/opasswd 2>/dev/null || stat -f "%Su:%Sg" /etc/security/opasswd)

  DETAILS+="opasswd file details:
Owner: $OPASSWD_OWNER
Permissions: $OPASSWD_PERM

"

  if [ "$OPASSWD_OWNER" != "root:root" ] || [ "$OPASSWD_PERM" -gt 600 ]; then
    STATUS="FAIL"
    REM="opasswd file ownership or permissions are insecure"
  fi
else
  DETAILS+="opasswd file not present

"
fi

# --------------------------------------------------
# Observation
# --------------------------------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Password policy and authentication controls align with security requirements"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="Password policy configuration requires review for policy alignment"
else
  SUMMARY="Password policy configuration does not meet security requirements"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 37: Restrict Root Login and Privileged Access
# ----------------------------------------------------------
CHECK="Restrict Root Login and Privileged Access"
EXPECTED="Root login must be restricted, only authorized users may use su, and privileged access must be logged"
STATUS="PASS"
REM="None"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/security/access.conf
- grep wheel /etc/group
- cat /var/log/secure or /var/log/auth.log"

# -------------------------
# access.conf check
# -------------------------
ACCESS_CONF="/etc/security/access.conf"

if [ -f "$ACCESS_CONF" ]; then
  CMD="grep -Ev '^[[:space:]]*#|^[[:space:]]*$' $ACCESS_CONF"
  run_cmd "$CMD"
  ACCESS_OUT="$CMD_OUT"

  DETAILS+="/etc/security/access.conf entries:
${ACCESS_OUT:-<none>}

"

  if echo "$ACCESS_OUT" | grep -qE '^\-:ALL EXCEPT.*wheel'; then
    DETAILS+="Root login restriction using wheel group is configured

"
  elif echo "$ACCESS_OUT" | grep -qE '^\+:'; then
    STATUS="REVIEW"
    REM="Review permissive access rules in /etc/security/access.conf"
    DETAILS+="Permissive access rules detected in access.conf

"
  fi
else
  STATUS="REVIEW"
  REM="Configure /etc/security/access.conf to restrict root login"
  DETAILS+="/etc/security/access.conf file not found

"
fi

# -------------------------
# wheel group verification
# -------------------------
CMD="grep '^wheel:' /etc/group"
run_cmd "$CMD"
WHEEL_OUT="$CMD_OUT"
DETAILS+="wheel group entry:
${WHEEL_OUT:-<not present>}

"

if [ -z "$WHEEL_OUT" ]; then
  STATUS="FAIL"
  REM="Ensure wheel group exists and is used to control privileged access"
fi

# -------------------------
# Verify root belongs to wheel
# -------------------------
if echo "$WHEEL_OUT" | grep -q 'root'; then
  DETAILS+="root is a member of the wheel group

"
else
  STATUS="REVIEW"
  REM="Verify whether root should be a member of the wheel group"
  DETAILS+="root is not listed in the wheel group

"
fi

# -------------------------
# su usage logging
# -------------------------
SECURE_LOG=""

if [ -f /var/log/secure ]; then
  SECURE_LOG="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
  SECURE_LOG="/var/log/auth.log"
fi

if [ -n "$SECURE_LOG" ]; then
  CMD="grep 'su(pam_unix)' $SECURE_LOG | tail -n 5"
  run_cmd "$CMD"
  SU_LOG_OUT="$CMD_OUT"

  DETAILS+="Recent su usage from $SECURE_LOG:
${SU_LOG_OUT:-<no recent entries>}

"
else
  STATUS="REVIEW"
  REM="Unable to locate authentication logs for su usage review"
  DETAILS+="Authentication log file not found

"
fi

# -------------------------
# Observation
# -------------------------
if [ "$STATUS" = "PASS" ]; then
  SUMMARY="Root login and privileged access are properly restricted and monitored"
elif [ "$STATUS" = "REVIEW" ]; then
  SUMMARY="Privileged access configuration requires review"
else
  SUMMARY="Weak or missing controls for privileged access detected"
fi

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 38: User and Group Management Review
# ----------------------------------------------------------
CHECK="User and Group Management Review"
EXPECTED="User and group configuration must align with documented policies; administrator access must be limited and appropriate"
STATUS="REVIEW"
REM="Review user and group assignments against documented policies"
DETAILS=""
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- cat /etc/group
- grep -E '^(wheel|sudo)' /etc/group"

# -------------------------
# Step 1: List users and groups
# -------------------------
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

DETAILS+="System users (/etc/passwd):
$PASSWD_OUT

"

CMD="cat /etc/group"
run_cmd "$CMD"
GROUP_OUT="$CMD_OUT"

DETAILS+="System groups (/etc/group):
$GROUP_OUT

"

# -------------------------
# Step 2: Identify administrator groups
# -------------------------
CMD="grep -E '^(wheel|sudo)' /etc/group"
run_cmd "$CMD"
ADMIN_GROUPS="$CMD_OUT"

DETAILS+="Administrator groups (wheel/sudo):
${ADMIN_GROUPS:-<none found>}

"

if [ -z "$ADMIN_GROUPS" ]; then
  STATUS="FAIL"
  REM="No administrator group (wheel/sudo) found"
fi

# -------------------------
# Step 3: Count admin users
# -------------------------
ADMIN_USERS=$(echo "$ADMIN_GROUPS" | awk -F: '{print $4}')

DETAILS+="Users with administrative access:
${ADMIN_USERS:-<none>}

"

# -------------------------
# Step 4: Duplicate user account review
# -------------------------
DUP_USERS=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)

DETAILS+="Duplicate user accounts:
${DUP_USERS:-<none detected>}

"

if [ -n "$DUP_USERS" ]; then
  STATUS="REVIEW"
  REM="Duplicate user accounts detected; review required"
fi

# -------------------------
# Observation
# -------------------------
SUMMARY="User and group information collected for audit review. Administrative access and user uniqueness require validation against organizational policy."

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 39: Logical Access Monitoring
# ----------------------------------------------------------
CHECK="Logical Access Monitoring"
EXPECTED="Logical access must be monitored regularly with documented review procedures"
STATUS="REVIEW"
REM="Review evidence of periodic logical access monitoring and policy compliance"
DETAILS=""

CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- ls -l /etc/passwd
- cat /var/log/secure or /var/log/auth.log"

# -------------------------
# User account population
# -------------------------
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

DETAILS+="Current user accounts (/etc/passwd):
$PASSWD_OUT

"

# -------------------------
# passwd file metadata
# -------------------------
CMD="ls -l /etc/passwd"
run_cmd "$CMD"
PASSWD_META="$CMD_OUT"

DETAILS+="/etc/passwd file metadata:
$PASSWD_META

"

# -------------------------
# Authentication logs
# -------------------------
AUTH_LOG=""

if [ -f /var/log/secure ]; then
  AUTH_LOG="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
  AUTH_LOG="/var/log/auth.log"
fi

if [ -n "$AUTH_LOG" ]; then
  CMD="tail -n 50 $AUTH_LOG"
  run_cmd "$CMD"
  AUTH_OUT="$CMD_OUT"

  DETAILS+="Recent authentication activity ($AUTH_LOG):
$AUTH_OUT

"
else
  DETAILS+="Authentication log not found (manual verification required)

"
fi

SUMMARY="Logical access data collected. Evidence must be reviewed to confirm periodic monitoring and compliance with access control procedures."

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"


# ----------------------------------------------------------
# CHECK 40: Logical Access Segregation of Duties
# ----------------------------------------------------------
CHECK="Logical Access Segregation of Duties"
EXPECTED="Access request, approval, provisioning, and monitoring duties must be segregated and privileged access restricted"
STATUS="REVIEW"
REM="Review segregation of duties and privileged access assignments against policy"
DETAILS=""

CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- cat /etc/group
- cat /etc/login.defs
- cat /etc/securetty"

# -------------------------
# User accounts
# -------------------------
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

DETAILS+="User accounts (/etc/passwd):
$PASSWD_OUT

"

# -------------------------
# Group memberships
# -------------------------
CMD="cat /etc/group"
run_cmd "$CMD"
GROUP_OUT="$CMD_OUT"

DETAILS+="Group configuration (/etc/group):
$GROUP_OUT

"

# -------------------------
# Privileged groups
# -------------------------
CMD="grep -E '^(wheel|sudo|root)' /etc/group"
run_cmd "$CMD"
PRIV_GROUPS="$CMD_OUT"

DETAILS+="Privileged groups (wheel/sudo/root):
${PRIV_GROUPS:-<none>}

"

# -------------------------
# Login policy
# -------------------------
if [ -f /etc/login.defs ]; then
  CMD="cat /etc/login.defs"
  run_cmd "$CMD"
  LOGIN_DEFS="$CMD_OUT"

  DETAILS+="Login policy (/etc/login.defs):
$LOGIN_DEFS

"
fi

# -------------------------
# Root login restriction
# -------------------------
if [ -f /etc/securetty ]; then
  CMD="cat /etc/securetty"
  run_cmd "$CMD"
  SECURETTY_OUT="$CMD_OUT"

  DETAILS+="Root login terminals (/etc/securetty):
$SECURETTY_OUT

"
fi

SUMMARY="User, group, and privileged access configuration collected. Segregation of duties and privileged access usage must be validated against organizational policy."

OBS="$SUMMARY

$CMDS_EXECUTED

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 41: Root Access Review
# ----------------------------------------------------------
CHECK="Root Access Review"
EXPECTED="Access to the root account is restricted to authorized administrators and is monitored"
STATUS="REVIEW"
REM="Validate identified root access and usage against approved privileged access documentation"
CMDS_EXECUTED="Commands executed:
- grep '^root:' /etc/passwd
- journalctl or tail of authentication logs (limited scope)"

# -------------------------
# Root account entry
# -------------------------
run_cmd "grep '^root:' /etc/passwd 2>/dev/null"
ROOT_PASSWD_OUT="$CMD_OUT"

# -------------------------
# Root access activity (performance-safe)
# -------------------------
if command -v journalctl >/dev/null 2>&1; then
  run_cmd "journalctl -n 200 --no-pager 2>/dev/null | grep -E 'su|sudo' | grep root || true"
else
  if [ -f /var/log/secure ]; then
    run_cmd "tail -n 500 /var/log/secure 2>/dev/null | grep -E 'su|sudo' | grep root || true"
  elif [ -f /var/log/auth.log ]; then
    run_cmd "tail -n 500 /var/log/auth.log 2>/dev/null | grep -E 'su|sudo' | grep root || true"
  else
    CMD_OUT="Authentication log not found"
  fi
fi

ROOT_LOG_OUT="$CMD_OUT"

# -------------------------
# Observation
# -------------------------
OBS="
Evidence reviewed:
- Root account configuration from /etc/passwd
- Recent root access activity from authentication logs (sample-based)

Root account entry:
${ROOT_PASSWD_OUT:-<not found>}

Recent root access events (limited review):
${ROOT_LOG_OUT:-<no recent root activity observed>}

Audit Note:
Log review is limited to recent activity for performance reasons.
Comprehensive historical review should be performed using centralized logging or SIEM solutions.

$CMDS_EXECUTED"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 42: Physical Security – Data Center Access
# ----------------------------------------------------------
CHECK="Physical Security – Data Center Access"
EXPECTED="Physical access to the data center is restricted to authorized personnel only"
STATUS="REVIEW"
REM="This is a manual control. Validate against physical access logs, badge records, and facility controls"
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd (sample only)"
CMD="/etc/passwd 2>/dev/null || true"
run_cmd "$CMD"
PASSWD_SAMPLE="$CMD_OUT"
OBS="Audit Context:
Physical security controls cannot be validated through operating system configuration.
This control requires manual verification through facility access management processes.

System Evidence (context only):
A sample of local system accounts is provided below for reference. This does not represent physical access authorization.

${PASSWD_SAMPLE:-<not available>}

$CMDS_EXECUTED"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 43: Generic Accounts Review
# ----------------------------------------------------------
CHECK="Generic Accounts Review"
EXPECTED="Generic accounts are restricted, approved, monitored, and appropriately managed"

STATUS="REVIEW"
REM="Investigate any generic accounts and confirm business justification, approvals, and monitoring"

CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- grep for potential generic account names
- review authentication logs"

# STEP 1: Review passwd for generic-style accounts
CMD="cat /etc/passwd"
run_cmd "$CMD"
PASSWD_OUT="$CMD_OUT"

GENERIC_ACCOUNTS=$(echo "$PASSWD_OUT" | awk -F: '
tolower($1) ~ /(admin|support|tech|test|shared|service|root)/ {print $1 ":" $7}
')

# STEP 2: Review authentication logs (OS dependent)
if [ -f /var/log/secure ]; then
  CMD="grep -i 'su' /var/log/secure 2>/dev/null | tail -n 20"
elif [ -f /var/log/auth.log ]; then
  CMD="grep -i 'su' /var/log/auth.log 2>/dev/null | tail -n 20"
else
  CMD="echo 'Authentication log not found'"
fi

run_cmd "$CMD"
AUTH_LOG_OUT="$CMD_OUT"
OBS="System Evidence:

Potential Generic Accounts (username:shell):
${GENERIC_ACCOUNTS:-<none identified>}

Authentication Evidence (sample):
${AUTH_LOG_OUT:-<not available>}

Audit Guidance:
Any generic accounts identified must have:
- Documented business justification
- Formal management approval
- Compensating controls (logging, monitoring, access restrictions)
- Evidence of accountability for usage

$CMDS_EXECUTED"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 44: Group Membership Review
# ----------------------------------------------------------
CHECK="Group Membership Review"
EXPECTED="Group memberships are appropriate, approved, and aligned with job responsibilities"
CMDS_EXECUTED="Commands executed:
- cat /etc/passwd
- cat /etc/group"

# Capture users and groups
run_cmd "cat /etc/passwd 2>/dev/null"
PASSWD_OUT="$CMD_OUT"
run_cmd "cat /etc/group 2>/dev/null"
GROUP_OUT="$CMD_OUT"

# Identify privileged groups
run_cmd "grep -E '^(root|wheel|sudo|adm):' /etc/group 2>/dev/null"
PRIV_GROUPS="$CMD_OUT"

STATUS="REVIEW"
REM="Validate group memberships with system owner and access approval records"

OBS="Client Evidence and Manual Review Procedures:
Review user and group configurations to confirm appropriate assignment of privileges.

Evidence reviewed:
- /etc/passwd for user accounts
- /etc/group for group definitions and memberships
- Privileged groups (root, wheel, sudo, adm)

Privileged group memberships:
${PRIV_GROUPS:-<none found>}

Audit Note:
Membership in privileged groups should be restricted, approved, and periodically reviewed.
Any exceptions or elevated access should be supported by documented business justification.

$CMDS_EXECUTED"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 45: Kernel Network Hardening (sysctl)
# ----------------------------------------------------------
CHECK="Kernel Network Hardening"
EXPECTED="Critical kernel network parameters must be explicitly hardened as per security baseline"
STATUS="PASS"
REM="None"
DETAILS=""

declare -A SYSCTL_EXPECTED=(
  ["net.ipv4.conf.all.rp_filter"]="1"
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.tcp_syncookies"]="1"
)

for key in "${!SYSCTL_EXPECTED[@]}"; do
  run_cmd "sysctl -n $key"
  VAL="$CMD_OUT"
  if [ "$VAL" != "${SYSCTL_EXPECTED[$key]}" ]; then
    STATUS="FAIL"
    REM="Update /etc/sysctl.conf or /etc/sysctl.d/*.conf with secure values and apply using sysctl --system"
    DETAILS+="$key = ${VAL:-not set} (Expected: ${SYSCTL_EXPECTED[$key]})"$'\n'
  else
    DETAILS+="$key = $VAL (Compliant)"$'\n'
  fi
done

OBS="Validated kernel network hardening parameters.

Findings:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 46: Firewall Rules Validation
# ----------------------------------------------------------
CHECK="Firewall Rules Validation"
EXPECTED="Firewall service must be active and explicitly configured with restrictive rules"
STATUS="PASS"
REM="None"
DETAILS=""

if systemctl is-active firewalld >/dev/null 2>&1; then
  run_cmd "firewall-cmd --list-all"
  DETAILS="firewalld is active with following rules:
$CMD_OUT"
elif systemctl is-active ufw >/dev/null 2>&1; then
  run_cmd "ufw status verbose"
  DETAILS="ufw is active with following rules:
$CMD_OUT"
else
  STATUS="FAIL"
  REM="Enable firewalld (RHEL) or ufw (Ubuntu) and configure default deny inbound rules"
  DETAILS="No active firewall service detected on the system"
fi

OBS="Firewall configuration review completed.

Details:
$DETAILS"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 47: Account Lockout Policy (faillock)
# ----------------------------------------------------------
CHECK="Account Lockout Policy"
EXPECTED="User accounts must be locked after defined consecutive authentication failures"
STATUS="PASS"
REM="None"

if grep -Rq pam_faillock /etc/pam.d; then
  OBS="pam_faillock is configured in PAM authentication stack, enforcing account lockout"
else
  STATUS="FAIL"
  REM="Configure pam_faillock in PAM (system-auth/common-auth) with deny and unlock_time values"
  OBS="pam_faillock configuration not found in PAM stack"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 48: Inactive / Never Logged-In Users
# ----------------------------------------------------------
CHECK="Inactive or Never Logged-In Users"
EXPECTED="Inactive or unused user accounts must be reviewed and removed"
STATUS="PASS"
REM="None"

INACTIVE_USERS=$(lastlog | awk '$NF=="**Never" {print $1}')

if [ -n "$INACTIVE_USERS" ]; then
  STATUS="REVIEW"
  REM="Review inactive users and lock or remove accounts that are no longer required"
  OBS="The following users have never logged in and require review:
$INACTIVE_USERS"
else
  OBS="No inactive or never logged-in user accounts were identified"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 49: World Writable Files
# ----------------------------------------------------------
CHECK="World Writable Files"
EXPECTED="System files must not have world-writable permissions"
STATUS="PASS"
REM="None"

run_cmd "find / -xdev -type f -perm -0002 2>/dev/null | head"
if [ -n "$CMD_OUT" ]; then
  STATUS="REVIEW"
  REM="Remove world-writable permissions using chmod o-w after validating business requirement"
  OBS="World-writable files detected (sample output):
$CMD_OUT"
else
  OBS="No world-writable files were detected on the system"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 50: Cron and At Access Control
# ----------------------------------------------------------
CHECK="Cron and At Access Control"
EXPECTED="Only authorized users should be permitted to schedule cron and at jobs"
STATUS="PASS"
REM="None"

DETAILS=""
[ -f /etc/cron.allow ] || DETAILS+="cron.allow file is missing"$'\n'
[ -f /etc/at.allow ] || DETAILS+="at.allow file is missing"$'\n'

if [ -n "$DETAILS" ]; then
  STATUS="REVIEW"
  REM="Create cron.allow and at.allow files and restrict permissions to authorized users"
fi

OBS="Cron and at access control validation completed.

Details:
${DETAILS:-cron.allow and at.allow files are present}"
add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 51: Core Dumps
# ----------------------------------------------------------
CHECK="Core Dumps"
EXPECTED="Core dumps must be disabled to prevent sensitive data exposure"
STATUS="PASS"
REM="None"

run_cmd "ulimit -c"
if [ "$CMD_OUT" != "0" ]; then
  STATUS="REVIEW"
  REM="Disable core dumps via /etc/security/limits.conf and fs.suid_dumpable"
  OBS="Core dumps are enabled (ulimit -c = $CMD_OUT)"
else
  OBS="Core dumps are disabled (ulimit -c = 0)"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"

# ----------------------------------------------------------
# CHECK 52: IPv6 Configuration
# ----------------------------------------------------------
CHECK="IPv6 Configuration"
EXPECTED="IPv6 should be disabled if not required for business use"
STATUS="PASS"
REM="None"

run_cmd "sysctl net.ipv6.conf.all.disable_ipv6"
if ! echo "$CMD_OUT" | grep -q "= 1"; then
  STATUS="REVIEW"
  REM="Disable IPv6 via sysctl if not required by application architecture"
  OBS="IPv6 is currently enabled on the system"
else
  OBS="IPv6 is disabled on the system"
fi

add_audit_row "$CHECK" "$EXPECTED" "$OBS" "$STATUS" "$REM"
echo -e "${BLUE}${CHECK}:${RESET} ${STATUS}"
# -------------------------
# Done: print CSV path (console only)
# -------------------------
echo
echo -e "${GREEN}Audit complete.${RESET} CSV report created at: ${BLUE}$CSV_FILE${RESET}"
