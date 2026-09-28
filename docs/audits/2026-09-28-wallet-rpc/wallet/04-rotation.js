async page => {
 const c=page.context(),r=c.arcora;
 r.oldKey=await page.evaluate(async()=>{window.oldKey=(await testClient.depositAccount()).apiKey;window.oldSocket=testClient.wsV1;return window.oldKey;});
 await page.getByRole('button',{name:'Recover',exact:true}).click();await page.getByLabel('Account owner id').fill(r.owner);
 r.b=await c.newPage();await r.b.goto('http://127.0.0.1:49399');await r.b.waitForFunction(()=>window.testClient?.wsV1?.readyState===1);
 r.b.on('console',m=>r.console.push(m.text()));
 await r.b.getByRole('button',{name:'Recover',exact:true}).click();await r.b.getByLabel('Account owner id').fill(r.owner);
 await page.getByRole('button',{name:/^(Sign & recover|Connect wallet & recover)$/}).click();
 await r.wallet.getByRole('button',{name:'Confirm',exact:true}).waitFor();
 await r.b.getByRole('button',{name:/^(Sign & recover|Connect wallet & recover)$/}).click();
 await r.b.getByRole('alert').waitFor();const busy=await r.b.getByRole('alert').innerText();if(!busy.includes('another tab'))throw new Error(busy);
 r.observations.push({id:'native-lock-busy',pass:true,alert:busy});
 await r.wallet.getByRole('button',{name:'Cancel',exact:true}).click();await page.getByRole('alert').waitFor();
 const rejection=await page.getByRole('alert').innerText(); const unchanged=await page.evaluate(async()=>testClient.storedGen===0&&(await testClient.depositAccount()).apiKey===window.oldKey);
 if(!unchanged||!rejection.includes('Wallet refused'))throw new Error('Rejected signature changed credentials');
 r.observations.push({id:'actual-rejection',pass:true,unchanged,rejection});
 await page.getByRole('button',{name:/^(Sign & recover|Connect wallet & recover)$/}).click();await r.wallet.getByRole('button',{name:'Confirm',exact:true}).click();
 await page.waitForFunction(()=>window.testClient?.storedGen===1&&testClient.wsV1?.readyState===1);
 await r.b.waitForFunction(()=>window.testClient?.storedGen===1&&testClient.wsV1?.readyState===1&&!!testClient.v1Owner);
 const result=await page.evaluate(async owner=>({generation:testClient.storedGen,oldHttpStatus:(await fetch('/v1/accounts/me',{headers:{'X-Api-Key':window.oldKey}})).status,oldSocketClosed:window.oldSocket.readyState===3,socketReplaced:testClient.wsV1!==window.oldSocket,ownerPreserved:testClient.v1Owner===owner}),r.owner);
 if(result.oldHttpStatus!==401||!result.oldSocketClosed||!result.socketReplaced||!result.ownerPreserved)throw new Error(JSON.stringify(result));
 r.newKey=await page.evaluate(async()=>(await testClient.depositAccount()).apiKey);
 if(!await r.b.evaluate(async k=>(await testClient.depositAccount()).apiKey===k,r.newKey))throw new Error('Sibling key mismatch');
 r.observations.push({id:'rotation-old-access-revoked',pass:true,...result},{id:'sibling-key-and-private-ws-adopted',pass:true});
 for(const p of [page,r.b]){await p.reload();await p.waitForFunction(()=>window.testClient?.storedGen===1&&testClient.wsV1?.readyState===1);const ok=await p.evaluate(async ({owner,key})=>testClient.v1Owner===owner&&(await testClient.depositAccount()).apiKey===key,{owner:r.owner,key:r.newKey});if(!ok)throw new Error('Reload identity mismatch');r.observations.push({id:p===page?'reload-a':'reload-b',pass:true,generation:1});}
 return r.observations;
}
