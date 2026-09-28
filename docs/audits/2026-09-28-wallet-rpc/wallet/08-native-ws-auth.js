async page => {
 const r=page.context().arcora;const rows=[];
 for(const [name,p] of [['a',r.a],['b',r.b]]){
  const frames=[];p.on('websocket',ws=>{if(ws.url().endsWith('/v1/ws'))ws.on('framereceived',f=>{try{const m=JSON.parse(String(f.payload));if(m.type==='authOk'||m.type==='error')frames.push({type:m.type,owner:m.owner,message:m.message});}catch{}});});
  await p.reload();await p.waitForFunction(()=>window.testClient?.storedGen===3 && !!testClient.v1Owner && testClient.wsV1?.readyState===1);
  if(!frames.some(m=>m.type==='authOk'&&m.owner===r.owner))throw new Error('Missing actual private WS authOk for '+name);
  const state=await p.evaluate(async owner=>({ownerPreserved:testClient.v1Owner===owner,generation:testClient.storedGen,accountStatus:(await fetch('/v1/accounts/me',{headers:{'X-Api-Key':(await testClient.depositAccount()).apiKey}})).status}),r.owner);
  if(!state.ownerPreserved||state.accountStatus!==200)throw new Error('Snapshot restart account mismatch');
  rows.push({tab:name,authOk:true,...state});
 }
 r.observations.push({id:'native-private-ws-auth-after-gateway-restart',pass:true,tabs:rows});return {gatewayRestart:'same durable snapshot, no reset',rows};
}
