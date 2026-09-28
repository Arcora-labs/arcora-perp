async page => {
 const c=page.context();
 const e=c.pages().find(p=>p.url().includes('chrome-extension:'));
 await e.getByRole('combobox').selectOption('English');
 await e.getByRole('button',{name:'Create a new wallet',exact:true}).click();
 await e.getByRole('button',{name:'Use Secret Recovery Phrase',exact:true}).click();
 const password='Disposable-'+Math.random().toString(36)+Math.random().toString(36);
 await e.getByRole('textbox',{name:'Create new password',exact:true}).fill(password);
 await e.getByRole('textbox',{name:'Confirm password',exact:true}).fill(password);
 await e.getByRole('checkbox').check();
 await e.getByRole('button',{name:'Create password',exact:true}).click();
 await e.getByRole('button',{name:'Maybe later',exact:true}).click();
 await e.getByRole('button',{name:'Remind me later',exact:true}).click();
 await e.getByRole('checkbox',{name:'Gather basic usage data'}).uncheck();
 await e.getByRole('button',{name:'Continue',exact:true}).click();
 await e.getByRole('button',{name:'Open wallet',exact:true}).click();
 const home=e.url().split('#')[0]; await e.goto(home);
 await e.getByRole('button',{name:'Account 1',exact:true}).waitFor();
 c.arcora={a:page,e,observations:[],console:[],urls:[],requests:[],socketFrames:[]};
 c.on('request',q=>{ if(q.url().startsWith('http://127.0.0.1:49399')) c.arcora.requests.push({url:q.url(),method:q.method(),authenticated:!!q.headers()['x-api-key']}); });
 page.on('console',m=>c.arcora.console.push(m.text()));
 await page.locator('button.wallet-btn').click();
 return {onboarded:true,provider:'Unmodified official MetaMask',noSeedRead:true};
}
