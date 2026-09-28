async page => {
 const r=page.context().arcora;
 const observation=await page.evaluate(key=>new Promise(resolve=>{const ws=new WebSocket('ws://127.0.0.1:49399/v1/ws');const events=[];const finish=()=>{ws.close();resolve(events);};const timer=setTimeout(finish,3000);ws.onopen=()=>{events.push({event:'open'});ws.send(JSON.stringify({type:'auth',apiKey:key}));};ws.onmessage=e=>{const m=JSON.parse(e.data);events.push({event:'message',type:m.type,message:m.message});if(m.type==='error'||m.type==='authOk'){clearTimeout(timer);finish();}};ws.onclose=e=>events.push({event:'close',code:e.code});}),r.oldKey);
 return observation;
}
