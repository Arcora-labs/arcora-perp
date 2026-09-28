async page => {
 const r=page.context().arcora;
 await page.evaluate(({address,digest})=>{window.binding=ethereum.request({method:'personal_sign',params:[digest,address]}).then(sig=>testClient.bindDepositAddress(address,sig)).then(()=>'bound',e=>e.message);},{address:r.address,digest:'0x9d3a80779981bf9f16fd90fc64d57cd26376382f4ae7b958d2b522d4debe1401'});
 await r.wallet.getByRole('button',{name:'Confirm',exact:true}).click();
 const result=await page.evaluate(()=>window.binding);if(result!=='bound')throw new Error(result);
 r.observations.push({id:'real-metamask-bind',pass:true});return r.observations;
}