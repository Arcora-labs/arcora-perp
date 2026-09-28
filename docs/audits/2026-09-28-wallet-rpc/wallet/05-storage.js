async page => {
 const r=page.context().arcora;
 r.aRequests=[];page.on('request',q=>r.aRequests.push({path:q.url().replace(/^https?:\/\/[^/]+/,''),method:q.method(),authenticated:!!q.headers()['x-api-key']}));
 await page.getByRole('button',{name:'Recover',exact:true}).click();await page.getByLabel('Account owner id').fill(r.owner);
 await page.evaluate(()=>{const original=Storage.prototype.setItem;Storage.prototype.setItem=function(k,v){if(k.startsWith('darkperp.v2Account:'))throw new DOMException('quota','QuotaExceededError');return original.call(this,k,v);};});
 await page.getByRole('button',{name:/^(Sign & recover|Connect wallet & recover)$/}).click();await r.wallet.getByRole('button',{name:'Confirm',exact:true}).click();
 await page.waitForFunction(()=>testClient.storedGen===2);
 const notice=await page.getByRole('status').innerText();
 const result=await page.evaluate(async()=>({generation:testClient.storedGen,storage:testClient.credentialStorage,savedGeneration:JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>k.startsWith('darkperp.v2Account:')))).recoveryNonce,accountStatus:(await fetch('/v1/accounts/me',{headers:{'X-Api-Key':(await testClient.depositAccount()).apiKey}})).status}));
 if(result.storage!=='session'||result.savedGeneration!==1||result.accountStatus!==200||!notice.includes('this tab only'))throw new Error(JSON.stringify(result));
 r.sessionKey=await page.evaluate(async()=>(await testClient.depositAccount()).apiKey);
 r.observations.push({id:'storage-quota-session-only',pass:true,controlledFault:'Storage.setItem credential write throws QuotaExceededError',notice,...result});
 const offset=r.aRequests.length;await page.reload();await page.waitForFunction(()=>!!window.testClient);await page.getByRole('button',{name:'Account',exact:true}).click();await page.getByText(/placeholders \(0\), not your/).waitFor();
 const registrations=r.aRequests.slice(offset).filter(q=>q.path==='/v1/accounts'&&q.method==='POST').length;if(registrations)throw new Error('Replacement registration');
 r.observations.push({id:'session-only-reload',pass:true,degradedVisible:true,replacementRegistrations:registrations});return r.observations.slice(-2);
}
