async page => {
 const c=page.context(),r=c.arcora;
 const stale=await page.evaluate(key=>new Promise((resolve,reject)=>{const ws=new WebSocket('ws://127.0.0.1:49399/v1/ws');const timer=setTimeout(()=>{ws.close();reject(new Error('stale WS timeout'));},10000);let authOk=false,error=false;ws.onopen=()=>ws.send(JSON.stringify({type:'auth',apiKey:key}));ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='authOk')authOk=true;if(m.type==='error')error=true;};ws.onclose=e=>{clearTimeout(timer);resolve({authOk,error,closeCode:e.code});};}),r.oldKey);
 if(stale.authOk||!stale.error)throw new Error('Old WS credential accepted');r.observations.push({id:'old-key-new-websocket-denied',pass:true,...stale});
 const offset=r.aRequests.length;await page.evaluate(()=>Object.defineProperty(navigator,'locks',{value:undefined,configurable:true}));
 await page.getByRole('button',{name:/^(Sign & recover|Connect wallet & recover)$/}).click();await page.getByRole('alert').waitFor();const noLock=await page.getByRole('alert').innerText();const posts=r.aRequests.slice(offset).filter(q=>q.method==='POST').length;
 if(!noLock.includes('cross-tab locking')||posts)throw new Error('Missing lock allowed mutation');r.observations.push({id:'missing-lock-fails-before-mutation',pass:true,alert:noLock,posts});
 await page.reload();await page.waitForFunction(()=>window.testClient?.storedGen===3&&testClient.wsV1?.readyState===1);await page.getByRole('button',{name:'Recover',exact:true}).click();
 const response=await page.request.get('http://127.0.0.1:49399');const csp=response.headers()['content-security-policy'];
 if(!csp?.includes("default-src 'none'")||!csp.includes("script-src 'self'"))throw new Error('Missing actual CSP');
 const secrets=[r.oldKey,r.newKey,r.sessionKey,r.finalKey];const captured=JSON.stringify({console:r.console,requests:r.requests,observations:r.observations});const leaks=secrets.filter(k=>captured.includes(k)||captured.includes(k.slice(2))).length;const violations=r.console.filter(s=>/violat.*content security policy|refused.*(script|connect).*directive/i.test(s));
 if(leaks||violations.length)throw new Error('Redaction/CSP check failed');
 r.observations.push({id:'actual-csp-and-redaction',pass:true,csp,credentialValuesChecked:secrets.length,credentialLeaks:leaks,cspViolations:violations.length});
 const counts={};for(const q of r.requests){const key=q.method+' '+q.url.replace('http://127.0.0.1:49399','');counts[key]=(counts[key]||0)+1;}
 return {browser:c.browser().version(),wallet:'MetaMask 13.50.0 official unmodified extension',scope:'Real wallet signing + native Rust gateway, no L1/token/proof',observations:r.observations,console:r.console,network:counts,redaction:'API credentials, Authorization headers, response bodies and raw signatures omitted; key leak comparisons performed in memory.'};
}
