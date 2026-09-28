async page => {
 const c=page.context(),r=c.arcora;
 const s=await c.browser().newBrowserCDPSession(); const ts=await s.send('Target.getTargets'); await s.detach();
 const target=ts.targetInfos.find(t=>t.type==='page'&&t.url.includes('/sidepanel.html#/connect/')); if(!target)throw new Error('No extension connect approval target');
 r.wallet=await c.newPage();await r.wallet.goto(target.url);
 await r.wallet.getByRole('button',{name:'Connect',exact:true}).click();
 await page.waitForFunction(async()=> (await ethereum.request({method:'eth_accounts'})).length===1);
 await page.locator('button.wallet-btn').click();
 const account=await page.evaluate(async()=>({address:(await ethereum.request({method:'eth_accounts'}))[0],owner:window.testClient.v1Owner,generation:testClient.storedGen}));
 r.owner=account.owner;r.address=account.address;
 return account;
}
