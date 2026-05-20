#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║               ⚡  T H U N D E R C L O U D  v2  ⚡                  ║
# ║     Cloud Environment Mapper — AWS · GCP · Azure · Yandex           ║
# ║                  Docker · Kubernetes · Pivot Recon                  ║
# ║          For authorized penetration testing use only                ║
# ╚══════════════════════════════════════════════════════════════════════╝
# Usage: bash ThunderCloud.sh [-o file] [-v] [-h]
#   -o  Also tee output to a file (default: console only)
#   -v  Verbose
#   -h  Help

set -uo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; Y='\033[1;33m'; G='\033[0;32m'
C='\033[0;36m'; B='\033[0;34m'; DIM='\033[2m'; BOLD='\033[1m'; RST='\033[0m'

# ── Globals ───────────────────────────────────────────────────────────────────
VERBOSE=0
OUTPUT_FILE=""
CLOUDS=()
FINDINGS=()
AWS_TOKEN=""

# ── Args ──────────────────────────────────────────────────────────────────────
while getopts ":o:vh" opt; do
  case $opt in
    o) OUTPUT_FILE="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) grep '^# ' "$0" | cut -c3-; exit 0 ;;
    *) echo "Unknown: -$OPTARG"; exit 1 ;;
  esac
done

# ── I/O ───────────────────────────────────────────────────────────────────────
_out() {
  echo -e "$*"
  [[ -n "$OUTPUT_FILE" ]] && echo -e "$*" >> "$OUTPUT_FILE"
}
log()     { _out "${C}[*]${RST} $*"; }
ok()      { _out "${G}[+]${RST} $*"; }
warn()    { _out "${Y}[!]${RST} $*"; }
crit()    { _out "${R}[!!]${RST} ${BOLD}$*${RST}"; }
vrb()     { [[ $VERBOSE -eq 1 ]] && _out "${DIM}[v] $*${RST}" || true; }
finding() { FINDINGS+=("$1"); crit "FINDING: $1"; }
section() {
  _out ""
  _out "${BOLD}${B}┌──────────────────────────────────────────────────────┐${RST}"
  _out "${BOLD}${B}│  ⚡ $*${RST}"
  _out "${BOLD}${B}└──────────────────────────────────────────────────────┘${RST}"
}

cmd() { command -v "$1" &>/dev/null; }

# ── HTTP wrappers — never abort on failure ─────────────────────────────────
_curl() { curl -sf --max-time 3 --connect-timeout 2 --retry 1 "$@" 2>/dev/null || true; }
imds_aws()   { _curl -H "X-aws-ec2-metadata-token: ${AWS_TOKEN:-}" "$@"; }
imds_gcp()   { _curl -H "Metadata-Flavor: Google" "$@"; }
imds_azure() { _curl -H "Metadata: true" "$@"; }

# minimal json pretty-print, no external deps
json() { python3 -m json.tool 2>/dev/null || cat; }
# python3 one-liner against stdin
jq_s() { python3 -c "import sys,json
d=json.load(sys.stdin)
$1" 2>/dev/null || true; }

# ─────────────────────────────────────────────────────────────────────────────
banner() {
  _out "${BOLD}${Y}"
  _out "  _____ _                     _           ____ _                 _  "
  _out " |_   _| |__  _   _ _ __   __| | ___ _ __/ ___| | ___  _   _  __| |"
  _out "   | | | '_ \| | | | '_ \ / _\` |/ _ \ '__| |   | |/ _ \| | | |/ _\` |"
  _out "   | | | | | | |_| | | | | (_| |  __/ |  | |___| | (_) | |_| | (_| |"
  _out "   |_| |_| |_|\__,_|_| |_|\__,_|\___|_|   \____|_|\___/ \__,_|\__,_|"
  _out "                                                  v2 — cloud map${RST}"
  _out "${R}  [!] Authorized penetration testing use only.${RST}"
}

# ─────────────────────────────────────────────────────────────────────────────
# SHARED: scan env vars for credentials
# ─────────────────────────────────────────────────────────────────────────────
scan_env_creds() {
  log "Env vars with credential-like names:"
  local found=0
  while IFS='=' read -r name value; do
    if echo "$name" | grep -qiE 'key|secret|token|pass|cred|auth|api|pwd|bearer|cert|private'; then
      warn "  $name = ${value:0:8}[...]"
      finding "Sensitive env var: $name"
      found=1
    fi
  done < <(env 2>/dev/null)
  [[ $found -eq 0 ]] && log "(none found)"
}

# ─────────────────────────────────────────────────────────────────────────────
# SHARED: scan filesystem for credential files
# ─────────────────────────────────────────────────────────────────────────────
scan_cred_files() {
  local patterns=(
    ~/.aws/credentials ~/.aws/config
    /root/.aws/credentials
    /home/*/.aws/credentials
    ~/.config/gcloud/application_default_credentials.json
    /root/.config/gcloud/application_default_credentials.json
    /home/*/.config/gcloud/application_default_credentials.json
    ~/.azure/accessTokens.json ~/.azure/msal_token_cache.json
    /root/.azure/accessTokens.json
    ~/.config/yandex-cloud/config.yaml
    /root/.config/yandex-cloud/config.yaml
    /home/*/.config/yandex-cloud/config.yaml
    /etc/yandex-cloud/*.json
    /var/run/secrets/kubernetes.io/serviceaccount/token
    /run/secrets/*.json /run/secrets/*.env
    /etc/credentials /etc/cloud/*.cfg
    /opt/app/*.env /app/*.env /srv/*.env
    /var/app/*.env /*.env
  )
  log "Credential files on disk:"
  local found=0
  for pattern in "${patterns[@]}"; do
    # shellcheck disable=SC2086
    for f in $pattern; do
      [[ -f "$f" ]] || continue
      ok "  Found: $f  ($(stat -c '%A %U:%G' "$f" 2>/dev/null || echo '?'))"
      finding "Credential file: $f"
      found=1
    done
  done
  [[ $found -eq 0 ]] && log "(none found)"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. DETECT ENVIRONMENT
# ─────────────────────────────────────────────────────────────────────────────
detect_all() {
  section "ENVIRONMENT DETECTION"

  # Docker
  if [[ -f /.dockerenv ]] || grep -qai 'docker\|containerd\|lxc' /proc/1/cgroup 2>/dev/null; then
    CLOUDS+=(DOCKER); ok "Docker container"
  fi

  # Kubernetes
  if [[ -d /var/run/secrets/kubernetes.io ]] || [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    CLOUDS+=(K8S); ok "Kubernetes pod"
  fi

  # AWS — try IMDSv2 first, fall back to v1
  AWS_TOKEN=$(_curl -X PUT \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
    "http://169.254.169.254/latest/api/token")
  local aws_probe
  aws_probe=$(imds_aws "http://169.254.169.254/latest/meta-data/instance-id")
  [[ -z "$aws_probe" ]] && aws_probe=$(_curl "http://169.254.169.254/latest/meta-data/instance-id")
  [[ -n "$aws_probe" ]] && { CLOUDS+=(AWS); ok "AWS  instance-id: $aws_probe"; }

  # GCP
  local gcp_probe
  gcp_probe=$(imds_gcp "http://metadata.google.internal/computeMetadata/v1/instance/id")
  [[ -n "$gcp_probe" ]] && { CLOUDS+=(GCP); ok "GCP  instance-id: $gcp_probe"; }

  # Azure
  local az_probe
  az_probe=$(imds_azure \
    "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text")
  [[ -n "$az_probe" ]] && { CLOUDS+=(AZURE); ok "Azure  vmId: $az_probe"; }

  # Yandex Cloud
  local ya_vendor
  ya_vendor=$(_curl "http://169.254.169.254/latest/vendor")
  if echo "$ya_vendor" | grep -qi 'yandex\|yc'; then
    CLOUDS+=(YANDEX); ok "Yandex Cloud"
  elif grep -qi 'yandex' /sys/class/dmi/id/product_name \
                          /sys/class/dmi/id/sys_vendor 2>/dev/null \
       || [[ -f /etc/yandex-cloud/bootstrap.sh ]]; then
    CLOUDS+=(YANDEX); ok "Yandex Cloud (DMI)"
  fi

  [[ ${#CLOUDS[@]} -eq 0 ]] && warn "No cloud/container environment detected."
  _out ""
  _out "${BOLD}  Detected: ${G}${CLOUDS[*]:-none}${RST}"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. DOCKER
# ─────────────────────────────────────────────────────────────────────────────
recon_docker() {
  section "DOCKER — Escape Surface & Credentials"

  # Privileged?
  local cap_eff
  cap_eff=$(awk '/CapEff/{print $2}' /proc/1/status 2>/dev/null || true)
  if [[ "$cap_eff" == "0000003fffffffff" || "$cap_eff" == "ffffffffffffffff" ]]; then
    finding "PRIVILEGED container (CapEff=$cap_eff) — host escape likely"
  else
    log "CapEff: ${cap_eff:-unknown}"
  fi

  # Capabilities detail
  if cmd capsh; then
    log "Effective capabilities:"; capsh --print 2>/dev/null | grep -i 'current\|bounding' || true
  fi

  # Docker socket
  if [[ -S /var/run/docker.sock ]]; then
    finding "Docker socket /var/run/docker.sock accessible — full host takeover"
    log "Containers via socket API:"
    _curl --unix-socket /var/run/docker.sock "http://localhost/containers/json" | \
      jq_s "[print(c['Names'][0], c['Image'], c['Status']) for c in d]"
    log "Images:"
    _curl --unix-socket /var/run/docker.sock "http://localhost/images/json" | \
      jq_s "[print(i.get('RepoTags','?')) for i in d]"
  else
    log "Docker socket not exposed"
  fi

  # Writable / interesting mounts
  log "Non-overlay mounts:"
  mount 2>/dev/null | grep -vE 'proc|sysfs|cgroup|tmpfs|devpts|mqueue|hugetlbfs|overlay' | \
  while read -r line; do
    _out "  $line"
    echo "$line" | grep -q 'rw' && finding "Writable non-overlay mount: $line"
  done

  for p in /host /mnt /hostfs /rootfs /host_root; do
    [[ -d "$p" ]] && finding "Possible host FS mount at $p"
  done

  scan_env_creds
  scan_cred_files
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. KUBERNETES
# ─────────────────────────────────────────────────────────────────────────────
recon_k8s() {
  section "KUBERNETES — RBAC · Secrets · Network · Pivot"

  local SA="/var/run/secrets/kubernetes.io/serviceaccount"
  [[ -f "$SA/token" ]] || { warn "No service account token — skipping K8S recon"; return; }

  local TOKEN CA NS API
  TOKEN=$(cat "$SA/token")
  CA="$SA/ca.crt"
  NS=$(cat "$SA/namespace" 2>/dev/null || echo "default")
  API="https://${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:${KUBERNETES_SERVICE_PORT:-443}"

  finding "K8S service account token present (ns: $NS)"

  kube() { _curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$API$1"; }
  kube_post() {
    _curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" -X POST -d "$2" "$API$1"
  }

  log "API server version:"
  kube "/version" | jq_s "print(d.get('gitVersion','?'))"

  log "Who am I (SelfSubjectReview):"
  kube_post "/apis/authorization.k8s.io/v1/selfsubjectreviews" \
    '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectReview"}' | \
    jq_s "print(d.get('status',{}).get('userInfo',{}))"

  # Permissions check helper
  can_i() {
    local result
    result=$(kube_post "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
      "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"resourceAttributes\":{\"verb\":\"$1\",\"resource\":\"$2\"}}}" | \
      jq_s "print(d.get('status',{}).get('allowed', False))")
    echo "$result"
  }

  log "Key permissions (SelfSubjectAccessReview):"
  for action_resource in "get secrets" "list secrets" "list pods" "list nodes" \
                          "get serviceaccounts" "create pods" "exec pods" \
                          "list namespaces" "get clusterrolebindings"; do
    local verb res allowed
    verb="${action_resource%% *}"; res="${action_resource##* }"
    allowed=$(can_i "$verb" "$res")
    [[ "$allowed" == *"True"* ]] && { ok "  CAN: $verb $res"; finding "K8S RBAC: allowed $verb $res"; } \
                                 || log "  CANNOT: $verb $res"
  done

  log "Pods in namespace '$NS':"
  kube "/api/v1/namespaces/$NS/pods" | \
    jq_s "[print(i['metadata']['name'], i['status'].get('podIP',''), i['status'].get('phase','')) for i in d.get('items',[])]"

  log "Secrets in '$NS' (names — fetch manually for values):"
  local sec
  sec=$(kube "/api/v1/namespaces/$NS/secrets" | \
    jq_s "[print(i['metadata']['name'], i.get('type','')) for i in d.get('items',[])]")
  [[ -n "$sec" ]] && { echo "$sec"; finding "K8S: secrets listed in ns $NS"; } \
    || warn "Cannot list secrets"

  log "ConfigMaps in '$NS':"
  kube "/api/v1/namespaces/$NS/configmaps" | \
    jq_s "[print(i['metadata']['name']) for i in d.get('items',[])]"

  log "All namespaces:"
  local ns
  ns=$(kube "/api/v1/namespaces" | \
    jq_s "[print(i['metadata']['name']) for i in d.get('items',[])]")
  [[ -n "$ns" ]] && { echo "$ns"; finding "K8S: can list all namespaces"; } \
    || warn "Cannot list namespaces"

  log "Nodes (IPs — pivot targets):"
  kube "/api/v1/nodes" | \
    jq_s "[print(i['metadata']['name'], [a['address'] for a in i.get('status',{}).get('addresses',[])]) for i in d.get('items',[])]" \
    && finding "K8S: node IPs visible" || true

  log "Services in '$NS' (internal pivot targets):"
  kube "/api/v1/namespaces/$NS/services" | \
    jq_s "[print(i['metadata']['name'], i['spec'].get('clusterIP',''), i['spec'].get('ports',[])) for i in d.get('items',[])]"

  log "ServiceAccounts in '$NS':"
  kube "/api/v1/namespaces/$NS/serviceaccounts" | \
    jq_s "[print(i['metadata']['name']) for i in d.get('items',[])]"

  log "ClusterRoleBindings (top 30):"
  kube "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" | \
    jq_s "[print(i['metadata']['name']) for i in d.get('items',[])]" | head -30 || true

  log "Cloud IMDS reachable from this pod?"
  for url in "http://169.254.169.254/latest/meta-data/instance-id" \
             "http://metadata.google.internal/computeMetadata/v1/instance/id" \
             "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text"; do
    local r; r=$(_curl "$url")
    [[ -n "$r" ]] && { ok "IMDS reachable: $url → $r"; finding "K8S pod can reach IMDS: $url"; }
  done

  scan_env_creds
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. AWS
# ─────────────────────────────────────────────────────────────────────────────
recon_aws() {
  section "AWS — Identity · Credentials · Permissions · Pivot"

  local IMDS="http://169.254.169.254/latest"

  aws_m() {
    [[ -n "$AWS_TOKEN" ]] && \
      _curl -H "X-aws-ec2-metadata-token: $AWS_TOKEN" "$IMDS/meta-data/$1" || \
      _curl "$IMDS/meta-data/$1"
  }
  aws_d() {
    [[ -n "$AWS_TOKEN" ]] && \
      _curl -H "X-aws-ec2-metadata-token: $AWS_TOKEN" "$IMDS/dynamic/$1" || \
      _curl "$IMDS/dynamic/$1"
  }

  log "Identity document:"
  aws_d "instance-identity/document" | json

  local region account_id
  region=$(aws_m "placement/region")
  account_id=$(aws_d "instance-identity/document" | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('accountId',''))" 2>/dev/null || true)
  log "Region: $region  |  Account: $account_id"

  # IAM role + temp creds
  local role
  role=$(aws_m "iam/security-credentials/")
  if [[ -n "$role" ]]; then
    finding "IAM role attached: $role — temp creds available via IMDS"
    local creds
    creds=$(aws_m "iam/security-credentials/$role")
    echo "$creds" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('  AccessKeyId :', d.get('AccessKeyId',''))
print('  Expiration  :', d.get('Expiration',''))
print('  Token       :', '(present)' if d.get('Token') else 'absent')
" 2>/dev/null || echo "$creds"
    # Export so aws cli picks them up
    export AWS_ACCESS_KEY_ID=$(echo "$creds" | python3 -c "import sys,json; print(json.load(sys.stdin).get('AccessKeyId',''))" 2>/dev/null || true)
    export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | python3 -c "import sys,json; print(json.load(sys.stdin).get('SecretAccessKey',''))" 2>/dev/null || true)
    export AWS_SESSION_TOKEN=$(echo "$creds" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Token',''))" 2>/dev/null || true)
  else
    warn "No IAM role on instance"
  fi

  log "User-data (check for secrets/cloud-init):"
  local ud
  ud=$([[ -n "$AWS_TOKEN" ]] && \
    _curl -H "X-aws-ec2-metadata-token: $AWS_TOKEN" "$IMDS/user-data" || \
    _curl "$IMDS/user-data")
  [[ -n "$ud" ]] && { echo "$ud"; finding "AWS user-data populated"; } || log "(empty)"

  scan_cred_files
  scan_env_creds

  cmd aws || { warn "aws cli not found — install for full enumeration"; return; }

  local A="aws --output json ${region:+--region $region}"

  log "Caller identity:"
  $A sts get-caller-identity 2>/dev/null | json \
    && finding "AWS: sts:GetCallerIdentity OK" || warn "sts:GetCallerIdentity denied"

  log "IAM users:"
  $A iam list-users 2>/dev/null | \
    jq_s "[print(u['UserName'], u.get('Arn','')) for u in d.get('Users',[])]" \
    && finding "AWS: iam:ListUsers OK" || warn "iam:ListUsers denied"

  log "IAM roles:"
  $A iam list-roles 2>/dev/null | \
    jq_s "[print(r['RoleName'], r.get('Arn','')) for r in d.get('Roles',[])]" | head -30 \
    && finding "AWS: iam:ListRoles OK" || warn "iam:ListRoles denied"

  log "Attached policies for current entity:"
  local my_arn
  my_arn=$($A sts get-caller-identity 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('Arn',''))" 2>/dev/null || true)
  if [[ "$my_arn" == *":user/"* ]]; then
    local username="${my_arn##*/}"
    $A iam list-attached-user-policies --user-name "$username" 2>/dev/null | json || true
    $A iam list-user-policies --user-name "$username" 2>/dev/null | json || true
  fi

  log "S3 buckets:"
  $A s3api list-buckets 2>/dev/null | \
    jq_s "[print(b['Name']) for b in d.get('Buckets',[])]" \
    && finding "AWS: s3:ListBuckets OK — potential data targets" || warn "s3:ListBuckets denied"

  log "EC2 instances:"
  $A ec2 describe-instances 2>/dev/null | \
    jq_s "[print(i.get('InstanceId'), i.get('PrivateIpAddress',''), i.get('PublicIpAddress','?'), i.get('State',{}).get('Name','')) for r in d.get('Reservations',[]) for i in r.get('Instances',[])]" \
    && finding "AWS: ec2:DescribeInstances OK — pivot targets visible" || warn "ec2:DescribeInstances denied"

  log "VPCs:"
  $A ec2 describe-vpcs 2>/dev/null | \
    jq_s "[print(v['VpcId'], v.get('CidrBlock','')) for v in d.get('Vpcs',[])]" || true

  log "Subnets:"
  $A ec2 describe-subnets 2>/dev/null | \
    jq_s "[print(s['SubnetId'], s.get('CidrBlock',''), s.get('AvailabilityZone','')) for s in d.get('Subnets',[])]" || true

  log "Security groups:"
  $A ec2 describe-security-groups 2>/dev/null | \
    jq_s "[print(g['GroupId'], g['GroupName']) for g in d.get('SecurityGroups',[])]" | head -20 || true

  log "Lambda functions:"
  $A lambda list-functions 2>/dev/null | \
    jq_s "[print(f['FunctionName'], f.get('Role','')) for f in d.get('Functions',[])]" \
    && finding "AWS: lambda:ListFunctions OK" || warn "lambda:ListFunctions denied"

  log "Secrets Manager:"
  $A secretsmanager list-secrets 2>/dev/null | \
    jq_s "[print(s['Name']) for s in d.get('SecretList',[])]" \
    && finding "AWS: secretsmanager:ListSecrets OK" || warn "secretsmanager:ListSecrets denied"

  log "SSM Parameter Store (top 20):"
  $A ssm describe-parameters 2>/dev/null | \
    jq_s "[print(p['Name'], p.get('Type','')) for p in d.get('Parameters',[])]" | head -20 \
    && finding "AWS: ssm:DescribeParameters OK" || warn "ssm:DescribeParameters denied"

  log "RDS instances:"
  $A rds describe-db-instances 2>/dev/null | \
    jq_s "[print(i['DBInstanceIdentifier'], i.get('Endpoint',{}).get('Address',''), i.get('Engine','')) for i in d.get('DBInstances',[])]" \
    && finding "AWS: rds:DescribeDBInstances OK — DB pivot targets" || warn "rds:DescribeDBInstances denied"

  log "EKS clusters:"
  $A eks list-clusters 2>/dev/null | \
    jq_s "[print(c) for c in d.get('clusters',[])]" \
    && finding "AWS: EKS clusters listed" || warn "eks:ListClusters denied"

  log "ECR repositories:"
  $A ecr describe-repositories 2>/dev/null | \
    jq_s "[print(r['repositoryName'], r.get('repositoryUri','')) for r in d.get('repositories',[])]" \
    && finding "AWS: ECR repos listed" || warn "ecr:DescribeRepositories denied"

  log "SNS topics:"
  $A sns list-topics 2>/dev/null | \
    jq_s "[print(t.get('TopicArn','')) for t in d.get('Topics',[])]" || true

  log "SQS queues:"
  $A sqs list-queues 2>/dev/null | \
    jq_s "[print(u) for u in d.get('QueueUrls',[])]" || true
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. GCP
# ─────────────────────────────────────────────────────────────────────────────
recon_gcp() {
  section "GCP — Identity · Credentials · Permissions · Pivot"

  local GMDS="http://metadata.google.internal/computeMetadata/v1"
  gm() { imds_gcp "$GMDS/$1"; }

  log "Instance info:"
  for f in project/project-id instance/name instance/zone instance/id \
            instance/machine-type \
            "instance/network-interfaces/0/ip" \
            "instance/network-interfaces/0/access-configs/0/external-ip"; do
    local v; v=$(gm "$f")
    [[ -n "$v" ]] && ok "  $f: $v"
  done

  local project_id; project_id=$(gm "project/project-id")
  local GCP_TOKEN=""

  log "Service accounts + tokens:"
  local sa_list; sa_list=$(gm "instance/service-accounts/")
  if [[ -n "$sa_list" ]]; then
    while IFS= read -r sa; do
      sa="${sa%/}"; [[ -z "$sa" ]] && continue
      local email; email=$(gm "instance/service-accounts/$sa/email")
      ok "  SA: $email"
      log "  Scopes: $(gm "instance/service-accounts/$sa/scopes")"
      local tok; tok=$(gm "instance/service-accounts/$sa/token")
      if [[ -n "$tok" ]]; then
        finding "GCP: access token for SA $email obtainable via metadata"
        GCP_TOKEN=$(echo "$tok" | \
          python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)
        log "  token prefix: ${GCP_TOKEN:0:20}..."
      fi
    done <<< "$sa_list"
  else
    warn "No service accounts attached"
  fi

  log "Instance attributes (may contain secrets):"
  gm "instance/attributes/" | while read -r attr; do
    [[ -z "$attr" ]] && continue
    local val; val=$(gm "instance/attributes/$attr")
    _out "  $attr = $val"
    echo "$attr" | grep -qiE 'key|secret|token|pass|cred' && finding "GCP: sensitive attribute: $attr"
  done

  log "Startup script:"
  local ss; ss=$(gm "instance/attributes/startup-script")
  [[ -n "$ss" ]] && { echo "$ss"; finding "GCP: startup-script in metadata"; } || log "(empty)"

  scan_cred_files
  scan_env_creds

  # REST fallback if no gcloud
  if ! cmd gcloud; then
    warn "gcloud not found"
    if [[ -n "$GCP_TOKEN" ]]; then
      log "REST API fallback with access token..."
      _curl -H "Authorization: Bearer $GCP_TOKEN" \
        "https://cloudresourcemanager.googleapis.com/v1/projects" | \
        jq_s "[print(p.get('projectId',''), p.get('name','')) for p in d.get('projects',[])]" \
        && finding "GCP REST: projects listed" || true
      _curl -H "Authorization: Bearer $GCP_TOKEN" \
        "https://compute.googleapis.com/compute/v1/projects/$project_id/aggregated/instances" | \
        python3 -c "
import sys,json
d=json.load(sys.stdin)
for zone,data in d.get('items',{}).items():
  for inst in data.get('instances',[]):
    ips=[i.get('networkIP','') for i in inst.get('networkInterfaces',[])]
    print(inst.get('name',''), zone, ips)
" 2>/dev/null && finding "GCP REST: compute instances listed" || true
      _curl -H "Authorization: Bearer $GCP_TOKEN" \
        "https://storage.googleapis.com/storage/v1/b?project=$project_id" | \
        jq_s "[print(b.get('name','')) for b in d.get('items',[])]" \
        && finding "GCP REST: GCS buckets listed" || true
    fi
    return
  fi

  log "gcloud config:"
  gcloud config list 2>/dev/null

  log "Projects:"
  gcloud projects list 2>/dev/null \
    && finding "GCP: projects listed" || warn "projects list denied"

  log "Compute instances:"
  gcloud compute instances list 2>/dev/null \
    && finding "GCP: compute instances listed — pivot targets" || warn "instances list denied"

  log "Firewall rules:"
  gcloud compute firewall-rules list 2>/dev/null \
    && finding "GCP: firewall rules visible" || warn "firewall-rules denied"

  log "GCS buckets:"
  gcloud storage buckets list 2>/dev/null \
    && finding "GCP: GCS buckets listed" || warn "buckets list denied"

  log "Secrets:"
  gcloud secrets list 2>/dev/null \
    && finding "GCP: Secret Manager secrets listed" || warn "secrets list denied"

  log "GKE clusters:"
  gcloud container clusters list 2>/dev/null \
    && finding "GCP: GKE clusters listed" || warn "GKE list denied"

  log "Cloud SQL instances:"
  gcloud sql instances list 2>/dev/null \
    && finding "GCP: Cloud SQL listed — DB pivot targets" || warn "SQL list denied"

  log "Cloud Functions:"
  gcloud functions list 2>/dev/null \
    && finding "GCP: Cloud Functions listed" || warn "functions list denied"

  log "IAM policy (project):"
  gcloud projects get-iam-policy "$project_id" 2>/dev/null | head -80 \
    && finding "GCP: project IAM policy readable" || warn "get-iam-policy denied"

  log "Service accounts:"
  gcloud iam service-accounts list 2>/dev/null \
    && finding "GCP: SA list OK" || warn "SA list denied"

  log "Service account keys:"
  gcloud iam service-accounts list --format='value(email)' 2>/dev/null | \
  while read -r sa_email; do
    local keys
    keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" 2>/dev/null)
    [[ -n "$keys" ]] && { ok "  Keys for $sa_email:"; echo "$keys"; \
      finding "GCP: SA key(s) for $sa_email"; }
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. AZURE
# ─────────────────────────────────────────────────────────────────────────────
recon_azure() {
  section "AZURE — Identity · Credentials · Permissions · Pivot"

  local AMDS="http://169.254.169.254/metadata"
  az_m() { imds_azure "$AMDS/$1"; }

  log "Instance metadata:"
  az_m "instance?api-version=2021-02-01" | json

  local sub_id
  sub_id=$(az_m "instance/compute/subscriptionId?api-version=2021-02-01&format=text")
  local AZURE_TOKEN=""

  log "Managed Identity token (management plane):"
  local mi
  mi=$(az_m "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")
  if [[ -n "$mi" ]]; then
    finding "Azure: Managed Identity token for management.azure.com obtainable"
    AZURE_TOKEN=$(echo "$mi" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)
    local exp
    exp=$(echo "$mi" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_on',''))" 2>/dev/null || true)
    log "  token prefix: ${AZURE_TOKEN:0:20}...  expires: $exp"
  fi

  log "Managed Identity token (Key Vault):"
  local mi_kv
  mi_kv=$(az_m "identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net")
  [[ -n "$mi_kv" ]] && { finding "Azure: Managed Identity token for vault.azure.net obtainable"; \
    echo "$mi_kv" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  expires_on:', d.get('expires_on','?'))" 2>/dev/null || true; }

  log "User-data:"
  local ud
  ud=$(az_m "instance/compute/userData?api-version=2021-01-01&format=text")
  [[ -n "$ud" ]] && { echo "$ud" | base64 -d 2>/dev/null || echo "$ud"; \
    finding "Azure: user-data present"; } || log "(empty)"

  scan_cred_files
  scan_env_creds

  # REST fallback
  if [[ -n "$AZURE_TOKEN" ]]; then
    log "REST API recon with MI token..."
    log "Resource groups:"
    _curl -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/$sub_id/resourcegroups?api-version=2021-04-01" | \
      jq_s "[print(g.get('name',''), g.get('location','')) for g in d.get('value',[])]" \
      && finding "Azure REST: resource groups listed" || true

    log "VMs:"
    _curl -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/$sub_id/providers/Microsoft.Compute/virtualMachines?api-version=2022-03-01" | \
      jq_s "[print(v.get('name',''), v.get('location','')) for v in d.get('value',[])]" \
      && finding "Azure REST: VMs listed — pivot targets" || true

    log "Storage accounts:"
    _curl -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/$sub_id/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01" | \
      jq_s "[print(s.get('name','')) for s in d.get('value',[])]" \
      && finding "Azure REST: storage accounts listed" || true

    log "Key Vaults:"
    _curl -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/$sub_id/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01" | \
      jq_s "[print(k.get('name',''), k.get('properties',{}).get('vaultUri','')) for k in d.get('value',[])]" \
      && finding "Azure REST: Key Vaults listed" || true

    log "Role assignments:"
    _curl -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/$sub_id/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | \
      jq_s "[print(r.get('properties',{}).get('roleDefinitionId','').split('/')[-1], r.get('properties',{}).get('principalId','')) for r in d.get('value',[])]" | head -20 \
      && finding "Azure REST: role assignments readable" || true
  fi

  cmd az || { warn "az cli not found"; return; }

  log "Account:"
  az account show 2>/dev/null | json \
    && finding "Azure CLI: authenticated" || warn "az account show failed"

  log "Subscriptions:"
  az account list 2>/dev/null | \
    jq_s "[print(s.get('id',''), s.get('name','')) for s in d]" || true

  log "Role assignments (what this identity can do):"
  az role assignment list --all 2>/dev/null | \
    jq_s "[print(r.get('roleDefinitionName',''), r.get('scope','')) for r in d]" \
    && finding "Azure CLI: role assignments readable" || warn "role assignment list denied"

  log "VMs:"
  az vm list 2>/dev/null | \
    jq_s "[print(v.get('name',''), v.get('location','')) for v in d]" \
    && finding "Azure CLI: VMs listed" || warn "vm list denied"

  log "Key Vaults:"
  az keyvault list 2>/dev/null | \
    jq_s "[print(k.get('name',''), k.get('properties',{}).get('vaultUri','')) for k in d]" \
    && finding "Azure CLI: Key Vaults listed" || warn "keyvault list denied"

  log "Storage accounts:"
  az storage account list 2>/dev/null | \
    jq_s "[print(s.get('name',''), s.get('primaryLocation','')) for s in d]" \
    && finding "Azure CLI: storage listed" || warn "storage list denied"

  log "AKS clusters:"
  az aks list 2>/dev/null | \
    jq_s "[print(k.get('name',''), k.get('location','')) for k in d]" \
    && finding "Azure CLI: AKS clusters listed" || warn "AKS list denied"

  log "Web / Function Apps:"
  az webapp list 2>/dev/null | \
    jq_s "[print(a.get('name',''), a.get('defaultHostName','')) for a in d]" \
    && finding "Azure CLI: web apps listed" || warn "webapp list denied"

  log "SQL Servers:"
  az sql server list 2>/dev/null | \
    jq_s "[print(s.get('name',''), s.get('fullyQualifiedDomainName','')) for s in d]" \
    && finding "Azure CLI: SQL servers listed — DB pivot targets" || warn "sql list denied"
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. YANDEX CLOUD
# ─────────────────────────────────────────────────────────────────────────────
recon_yandex() {
  section "YANDEX CLOUD — Identity · Credentials · Permissions · Pivot"

  local YMDS="http://169.254.169.254/latest"
  ym() { _curl "$YMDS/$1"; }

  log "Identity document:"
  ym "dynamic/instance-identity/document" | json

  log "Instance metadata:"
  for f in meta-data/instance-id meta-data/local-ipv4 meta-data/public-ipv4 \
            meta-data/placement/availability-zone; do
    local v; v=$(ym "$f")
    [[ -n "$v" ]] && ok "  $f: $v"
  done

  log "IAM token via metadata:"
  local YC_TOKEN=""
  # Yandex exposes IAM token at this path
  local raw_tok
  raw_tok=$(ym "meta-data/iam-token" 2>/dev/null || true)
  [[ -z "$raw_tok" ]] && raw_tok=$(imds_gcp \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    2>/dev/null || true)
  if [[ -n "$raw_tok" ]]; then
    finding "Yandex Cloud: IAM token obtainable via metadata"
    YC_TOKEN=$(echo "$raw_tok" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token', d.get('iamToken','')))" \
      2>/dev/null || echo "$raw_tok")
    log "  token prefix: ${YC_TOKEN:0:20}..."
  fi

  log "User-data:"
  local ud; ud=$(ym "user-data")
  [[ -n "$ud" ]] && { echo "$ud"; finding "Yandex: user-data present"; } || log "(empty)"

  scan_cred_files
  scan_env_creds

  # REST fallback
  if [[ -n "$YC_TOKEN" ]] && ! cmd yc; then
    warn "yc cli not found — using REST API"
    log "Clouds:"
    _curl -H "Authorization: Bearer $YC_TOKEN" \
      "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds" | \
      jq_s "[print(c.get('id',''), c.get('name','')) for c in d.get('clouds',[])]" \
      && finding "Yandex REST: clouds listed" || true

    log "Folders:"
    _curl -H "Authorization: Bearer $YC_TOKEN" \
      "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders" | \
      jq_s "[print(f.get('id',''), f.get('name','')) for f in d.get('folders',[])]" || true
    return
  fi

  cmd yc || { warn "yc cli not found and no token — cannot enumerate further"; return; }

  log "Clouds:"
  yc resource-manager cloud list 2>/dev/null \
    && finding "Yandex: clouds listed" || warn "cloud list denied"

  log "Folders:"
  yc resource-manager folder list 2>/dev/null \
    && finding "Yandex: folders listed" || warn "folder list denied"

  log "IAM service accounts:"
  yc iam service-account list 2>/dev/null \
    && finding "Yandex: SA list OK" || warn "SA list denied"

  log "Access bindings:"
  local folder_id
  folder_id=$(yc config get folder-id 2>/dev/null || true)
  [[ -n "$folder_id" ]] && \
    yc resource-manager folder list-access-bindings "$folder_id" 2>/dev/null \
    && finding "Yandex: access bindings readable" || warn "access bindings denied"

  log "Compute instances:"
  yc compute instance list 2>/dev/null \
    && finding "Yandex: compute instances listed — pivot targets" || warn "compute list denied"

  log "VPC networks:"
  yc vpc network list 2>/dev/null \
    && finding "Yandex: VPC networks visible" || warn "VPC list denied"

  log "Subnets:"
  yc vpc subnet list 2>/dev/null || true

  log "Object Storage buckets:"
  yc storage bucket list 2>/dev/null \
    && finding "Yandex: storage buckets listed" || warn "storage list denied"

  log "Lockbox secrets:"
  yc lockbox secret list 2>/dev/null \
    && finding "Yandex: Lockbox secrets listed" || warn "Lockbox denied"

  log "Managed PostgreSQL:"
  yc managed-postgresql cluster list 2>/dev/null \
    && finding "Yandex: managed-postgresql listed — DB pivot" || true
  log "Managed MySQL:"
  yc managed-mysql cluster list 2>/dev/null \
    && finding "Yandex: managed-mysql listed — DB pivot" || true
  log "Managed Redis:"
  yc managed-redis cluster list 2>/dev/null || true

  log "Serverless Functions:"
  yc serverless function list 2>/dev/null \
    && finding "Yandex: serverless functions listed" || warn "functions denied"

  log "Container Registry:"
  yc container registry list 2>/dev/null || true

  log "Managed K8S clusters:"
  yc managed-kubernetes cluster list 2>/dev/null \
    && finding "Yandex: K8S clusters listed" || warn "K8S list denied"

  log "API Gateways:"
  yc serverless api-gateway list 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
summary() {
  _out ""
  _out "${BOLD}${Y}╔══════════════════════════════════════════════════════╗${RST}"
  _out "${BOLD}${Y}║              ⚡  FINDINGS SUMMARY                   ║${RST}"
  _out "${BOLD}${Y}╚══════════════════════════════════════════════════════╝${RST}"
  if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    _out "${G}  No critical findings.${RST}"
  else
    local i=1
    for f in "${FINDINGS[@]}"; do
      _out "  ${R}[F${i}]${RST} $f"
      ((i++))
    done
  fi
  _out ""
  _out "${DIM}  Clouds mapped : ${CLOUDS[*]:-none}${RST}"
  _out "${DIM}  Finished      : $(date)${RST}"
  [[ -n "$OUTPUT_FILE" ]] && _out "${G}  Report saved  : $OUTPUT_FILE${RST}"
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  banner
  [[ -n "$OUTPUT_FILE" ]] && : > "$OUTPUT_FILE"

  detect_all

  for cloud in "${CLOUDS[@]}"; do
    case "$cloud" in
      DOCKER) recon_docker ;;
      K8S)    recon_k8s    ;;
      AWS)    recon_aws    ;;
      GCP)    recon_gcp    ;;
      AZURE)  recon_azure  ;;
      YANDEX) recon_yandex ;;
    esac
  done

  [[ ${#CLOUDS[@]} -eq 0 ]] && warn "Nothing to map."

  summary
}

main "$@"