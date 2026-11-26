import express from 'express';
import {createHash,randomBytes,pbkdf2,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import {openDb} from './db.mjs';

const HOME_MSG='Em casa você só consegue ver. Para fazer isso, procure o professor na escola.';
const tokenHash=t=>createHash('sha256').update(t).digest('hex');
const pbk=(pw,salt)=>new Promise((res,rej)=>pbkdf2(pw,salt,600000,32,'sha256',(e,k)=>e?rej(e):res(k)));
function fail(msg,status=400){const e=new Error(msg);e.status=status;throw e}
function sameKey(a,b){const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length===y.length&&x.length>0&&timingSafeEqual(x,y)}

export async function createPortal({db,syncKey,distDir,now=()=>Date.now()}){
  if(!syncKey||String(syncKey).length<24)throw new Error('SYNC_KEY precisa ter pelo menos 24 caracteres.');
  const q=db.q;
  const app=express();app.disable('x-powered-by');app.set('trust proxy',1);
  app.use((req,res,next)=>{res.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'",'Strict-Transport-Security':'max-age=15552000'});next()});
  app.use(express.json({limit:'6mb'}));
  // limite simples por IP para login e sync
  const hits=new Map();
  const limit=(name,max,ms)=>(req,res,next)=>{const k=name+':'+req.ip,t=now(),a=(hits.get(k)||[]).filter(x=>t-x<ms);if(a.length>=max)return res.status(429).json({error:'Calma! Tente de novo daqui a pouco.'});a.push(t);hits.set(k,a);if(hits.size>5000)for(const [kk,v] of hits)if(!v.some(x=>t-x<ms))hits.delete(kk);next()};
  const snap=async(kind,k)=>{const r=await q('SELECT data,updated_ms FROM educa_snap WHERE kind=? AND k=?',[kind,k]);return r[0]?{data:JSON.parse(r[0].data),updated_ms:Number(r[0].updated_ms)}:null};
  const auth=async(req,res,next)=>{try{const token=req.get('authorization')?.replace(/^Bearer /,'');if(!token||!/^[a-f0-9]{64}$/.test(token))fail('Entre de novo, por favor.',401);const r=await q('SELECT role,subject_id,expires FROM educa_sessions WHERE token_hash=?',[tokenHash(token)]);const s=r[0];if(!s||Number(s.expires)<now())fail('Entre de novo, por favor.',401);req.user={role:s.role,id:Number(s.subject_id),th:tokenHash(token)};next()}catch(e){next(e)}};

  app.get('/healthz',(req,res)=>res.json({ok:true}));
  app.get('/api/public',async(req,res,next)=>{try{const m=(await snap('meta','public'))?.data||{};res.json({version:'3.0',name:m.name||'Banco Educa',color:m.color||'#176b55',logo:m.logo||'',currency:m.currency||'R$',setup:false,home:true})}catch(e){next(e)}});

  app.post('/api/login',limit('login',40,15*60000),async(req,res,next)=>{try{
    const p=req.body||{};
    if(p.role==='admin')fail('O gerente não entra por aqui.',403);
    if(!['student','teacher'].includes(p.role))fail('Perfil inválido.');
    const login=String(p.login||'').trim().toUpperCase().slice(0,60),pw=String(p.password||'');
    if(!login||pw.length>128)fail('Usuário/conta ou senha incorretos.',401);
    const key='login:'+p.role+':'+login;
    const at=(await q('SELECT failures,locked FROM educa_attempts WHERE k=?',[key]))[0];
    if(at&&Number(at.locked)>now())fail('Calma! Tente de novo daqui a pouco.',429);
    const acc=await snap('account',p.role+':'+login);
    const row=acc?.data;
    let ok=false;
    if(row&&/^\d{4}$/.test(pw)&&row.senha_hash){const h=await pbk(pw,row.senha_salt);ok=timingSafeEqual(h,Buffer.from(row.senha_hash,'hex'))}
    else await pbk('0000','00000000000000000000000000000000'); // tempo parecido
    if(!ok){const n=(at?Number(at.failures):0)+1;const lock=n>=5?now()+Math.min(60,5*2**Math.min(4,n-5))*60000:0;
      await q('INSERT INTO educa_attempts(k,failures,locked) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET failures=excluded.failures,locked=excluded.locked',[key,n,lock]);
      fail(n===4?'Senha incorreta. Mais um erro e o acesso fica parado por um tempo.':'Usuário/conta ou senha incorretos.',401)}
    if(row.blocked)fail('Conta bloqueada. Procure o gerente na escola.',403);
    if(row.status&&row.status!=='ativa')fail('Sua conta ainda não está pronta. Fale com o professor.',403);
    if(row.must_change||!row.pin_ready)fail('Primeiro acesso: troque a senha provisória na escola. Depois você entra aqui.',403);
    await q('DELETE FROM educa_attempts WHERE k=?',[key]);
    await q('DELETE FROM educa_sessions WHERE expires<?',[now()]);
    const token=randomBytes(32).toString('hex');
    await q('INSERT INTO educa_sessions(token_hash,role,subject_id,expires) VALUES(?,?,?,?)',[tokenHash(token),p.role,row.id,now()+8*3600000]);
    res.json({token,role:p.role,must_change:false});
  }catch(e){next(e)}});

  app.post('/api/logout',auth,async(req,res,next)=>{try{await q('DELETE FROM educa_sessions WHERE token_hash=?',[req.user.th]);res.json({ok:true})}catch(e){next(e)}});

  app.get('/api/data',auth,async(req,res,next)=>{try{
    const s=await snap('data:'+req.user.role,String(req.user.id));
    if(!s)fail('Os dados ainda não chegaram da escola. Tente de novo mais tarde.',503);
    const sync=await snap('meta','sync');
    const reqs=await q("SELECT id,action,status,reason,summary,created_ms,done_ms FROM educa_requests WHERE role=? AND subject_id=? AND action NOT IN ('msgResponder','msgLer') ORDER BY created_ms DESC LIMIT 30",[req.user.role,req.user.id]);
    const msgWait=(await q("SELECT summary FROM educa_requests WHERE role=? AND subject_id=? AND action='msgResponder' AND status='esperando' ORDER BY created_ms",[req.user.role,req.user.id])).map(r=>r.summary);
    const waiting=Number((await q("SELECT COALESCE(SUM(spend),0) n FROM educa_requests WHERE role=? AND subject_id=? AND status='esperando'",[req.user.role,req.user.id]))[0]?.n||0);
    const base=Number(s.data.student?.available_balance??s.data.student?.balance??0);
    let out={...s.data};let free=null;
    if(req.user.role==='student'){
      // Valores já com os pedidos que esperam: o mesmo número em todas as telas do aluno em casa
      const pend=await q("SELECT action,payload FROM educa_requests WHERE role=? AND subject_id=? AND status='esperando'",[req.user.role,req.user.id]);
      let dBal=0,dSav=0;
      for(const r of pend){let p={};try{p=JSON.parse(r.payload)}catch{}const c=Math.round(Number(p.amount||0)*100);
        if(r.action==='transferirPix')dBal-=c;
        else if(r.action==='poupancaGuardar'){dBal-=c;dSav+=c}
        else if(r.action==='poupancaTirar'){dBal+=c;dSav-=c}
        else if(r.action==='jogosComprarMoedas')dBal-=Number(dat_coinPrice(s.data))*Number(p.qty||0)}
      free=Math.max(0,base+dBal);
      if(out.student){out.student={...out.student,available_balance:free};if(out.student.balance!=null)out.student.balance_with_requests=free}
      if(out.savings){const sv=out.savings;out.savings={...sv,balance:Math.max(0,Number(sv.balance||0)+dSav),available:Math.max(0,Number(sv.available||0)+Math.min(0,dSav)),pending:pend.some(r=>String(r.action).startsWith('poupanca'))}}
    }
    res.json({...out,home:{online:true,updated_at:sync?.data?.updated_at||null,received_ms:sync?.updated_ms||null,can_act:true,msg_pending:msgWait,free_balance:free,waiting_spend:waiting,requests:reqs.map(r=>({...r,created_ms:Number(r.created_ms),done_ms:r.done_ms?Number(r.done_ms):null}))}});
  }catch(e){next(e)}});

  // Sincronizador do computador da escola
  const syncAuth=(req,res,next)=>sameKey(req.get('x-sync-key'),syncKey)?next():res.status(401).json({error:'Chave inválida.'});
  app.post('/api/sync',limit('sync',120,60000),syncAuth,async(req,res,next)=>{try{
    const b=req.body||{};let n=0;const t=now();
    for(const it of Array.isArray(b.items)?b.items:[]){
      if(!['account','data:student','data:teacher','meta'].includes(it?.kind)||typeof it.k!=='string'||it.k.length>80||it.data===undefined)continue;
      await q('INSERT INTO educa_snap(kind,k,hash,data,updated_ms) VALUES(?,?,?,?,?) ON CONFLICT(kind,k) DO UPDATE SET hash=excluded.hash,data=excluded.data,updated_ms=excluded.updated_ms',[it.kind,it.k,String(it.hash||''),JSON.stringify(it.data),t]);n++}
    if(b.keep&&typeof b.keep==='object')for(const kind of ['account','data:student','data:teacher']){
      if(!Array.isArray(b.keep[kind]))continue;const keep=new Set(b.keep[kind].map(String));
      const rows=await q('SELECT k FROM educa_snap WHERE kind=?',[kind]);
      for(const r of rows)if(!keep.has(r.k))await q('DELETE FROM educa_snap WHERE kind=? AND k=?',[kind,r.k])}
    if(b.updated_at)await q('INSERT INTO educa_snap(kind,k,hash,data,updated_ms) VALUES(?,?,?,?,?) ON CONFLICT(kind,k) DO UPDATE SET data=excluded.data,updated_ms=excluded.updated_ms',['meta','sync','',JSON.stringify({updated_at:String(b.updated_at).slice(0,40)}),t]);
    res.json({ok:true,items:n});
  }catch(e){next(e)}});
  app.get('/api/sync/hashes',syncAuth,async(req,res,next)=>{try{const rows=await q('SELECT kind,k,hash FROM educa_snap');res.json(Object.fromEntries(rows.map(r=>[r.kind+'|'+r.k,r.hash])))}catch(e){next(e)}});

  // ---------- ações em casa: viram PEDIDOS; só o computador da escola decide e aplica ----------
  const norm=t=>String(t||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
  const dat_coinPrice=d=>Number(d?.games?.coin_price||0);
  const num=(v,min,max,msg)=>{const n=Number(String(v).replace(',','.'));if(!Number.isFinite(n)||n<min||n>max)fail(msg);return n};
  const brl=c=>'R$ '+(c/100).toFixed(2).replace('.',',');
  const pendingSpend=async(role,id)=>Number((await q("SELECT COALESCE(SUM(spend),0) n FROM educa_requests WHERE role=? AND subject_id=? AND status='esperando'",[role,id]))[0]?.n||0);
  const verifyPin=async(id,pin)=>{
    const acc=(await q("SELECT data FROM educa_snap WHERE kind='account' AND k LIKE 'student:%'",[])).map(r=>JSON.parse(r.data)).find(a=>a.id===id);
    if(!acc||!/^\d{4}$/.test(String(pin||'')))fail('Digite a sua senha de 4 números.',403);
    const key='pin:'+id,at=(await q('SELECT failures,locked FROM educa_attempts WHERE k=?',[key]))[0];
    if(at&&Number(at.locked)>now())fail('Calma! Tente de novo daqui a pouco.',429);
    const h=await pbk(String(pin),acc.senha_salt);
    if(!timingSafeEqual(h,Buffer.from(acc.senha_hash,'hex'))){const n=(at?Number(at.failures):0)+1;const lock=n>=4?now()+10*60000:0;await q('INSERT INTO educa_attempts(k,failures,locked) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET failures=excluded.failures,locked=excluded.locked',[key,n,lock]);fail('Senha incorreta.',403)}
    await q('DELETE FROM educa_attempts WHERE k=?',[key]);
  };
  const HOME_STUDENT=['consultarPix','transferirPix','solicitarEmprestimo','poupancaGuardar','poupancaTirar','jogosComprarMoedas','msgResponder','msgLer'];
  const HOME_TEACHER=['registrarMovimentacao','registrarMulta','msgResponder','msgLer'];
  app.post('/api/action',auth,limit('action',60,60000),async(req,res,next)=>{try{
    const {action,payload:p={}}=req.body||{};const role=req.user.role,id=req.user.id;
    if(!(role==='student'?HOME_STUDENT:HOME_TEACHER).includes(action))fail(HOME_MSG,403);
    const dat=(await snap('data:'+role,String(id)))?.data;if(!dat)fail('Os dados ainda não chegaram da escola. Tente de novo mais tarde.',503);
    if(action==='consultarPix'){
      const acct=String(p.account||'').trim().toUpperCase().slice(0,20);
      const rows=await q("SELECT k,data FROM educa_snap WHERE kind='account' AND k=?",['student:'+acct]);
      const a=rows[0]&&JSON.parse(rows[0].data);
      if(!a||a.id===id||!a.first_name||a.status!=='ativa')fail('Conta não encontrada.');
      return res.json({id:a.id,name:a.first_name,account:acct});
    }
    const key=req.get('Idempotency-Key');if(!key||!/^[a-zA-Z0-9-]{16,80}$/.test(key))fail('Chave de operação inválida.');
    const rid='home-'+key.slice(0,70);
    const prior=(await q('SELECT id,status FROM educa_requests WHERE id=?',[rid]))[0];
    if(prior)return res.json({request_id:prior.id,status:prior.status,repeated:true});
    const pend=Number((await q("SELECT COUNT(*) n FROM educa_requests WHERE role=? AND subject_id=? AND status='esperando'",[role,id]))[0].n);
    if(pend>=8)fail('Você já tem muitos pedidos esperando. Espere o professor responder.',429);
    let out={},spend=0,summary='';
    if(action==='msgResponder'||action==='msgLer'){
      if(action==='msgResponder'){const body=String(p.body||'').trim().slice(0,500);if(!body)fail('Escreva a mensagem.');out={body};summary=body}
    }else if(role==='student'){
      const free=Number(dat.student?.available_balance??dat.student?.balance??0)-await pendingSpend('student',id);
      if(action==='transferirPix'){
        if(!dat.config?.permitir_pix)fail('O Pix ainda não está liberado.');
        const amount=num(p.amount,0.01,100000,'Digite um valor de Pix certo.');const cents=Math.round(amount*100);
        if(cents>free)fail('Você não tem saldo livre para isso agora. Seu saldo livre é '+brl(Math.max(0,free))+'.');
        await verifyPin(id,p.pin);
        const acct=String(p.account||'').trim().toUpperCase().slice(0,20);const a=(await q("SELECT data FROM educa_snap WHERE kind='account' AND k=?",['student:'+acct]))[0];const ad=a&&JSON.parse(a.data);
        if(!ad||ad.id!==Number(p.recipient_id)||ad.id===id)fail('Confira o nome de quem vai receber.');
        out={account:acct,recipient_id:ad.id,amount};spend=cents;summary='Pix de '+brl(cents)+' para '+ad.first_name;
      }else if(action==='poupancaGuardar'){
        const amount=num(p.amount,0.01,100000,'Digite um valor certo.');const cents=Math.round(amount*100);
        if(cents>free)fail('Você não tem saldo livre para isso agora. Seu saldo livre é '+brl(Math.max(0,free))+'.');
        out={amount};spend=cents;summary='Guardar '+brl(cents)+' no cofrinho';
      }else if(action==='poupancaTirar'){
        const amount=num(p.amount,0.01,100000,'Digite um valor certo.');out={amount};summary='Tirar '+brl(Math.round(amount*100))+' do cofrinho';
      }else if(action==='jogosComprarMoedas'){
        const qty=Math.round(num(p.qty,1,20,'Escolha de 1 a 20 moedas.'));const price=Number(dat.games?.coin_price||0);if(price<=0)fail('A compra de moedas está desligada.');
        const cents=price*qty;if(cents>free)fail('Você não tem saldo livre para isso agora. Seu saldo livre é '+brl(Math.max(0,free))+'.');
        out={qty};spend=cents;summary='Comprar '+qty+' moeda'+(qty>1?'s':'')+' ('+brl(cents)+')';
      }else if(action==='solicitarEmprestimo'){
        const amount=num(p.amount,0.01,1000000,'Digite um valor certo.');const count=Math.round(num(p.count,1,36,'Escolha as parcelas.'));
        const room=Number(dat.student?.loan_free??dat.student?.loan_limit??0);if(Math.round(amount*100)>room)fail('Esse valor passa do seu limite. Você ainda pode pedir '+brl(room)+'.');
        await verifyPin(id,p.pin);out={amount,count};summary='Pedir empréstimo de '+brl(Math.round(amount*100))+' em '+count+' parcela'+(count>1?'s':'');
      }
    }else{
      const st=(dat.students||[]).find(s=>s.id===Number(p.student_id));if(!st)fail('Aluno fora da sua turma.',403);
      if(action==='registrarMovimentacao'){
        const amount=num(p.amount,0.01,100000,'Digite um valor certo.');const kind=['credito','bonus'].includes(p.kind)?p.kind:'credito';
        out={student_id:st.id,direction:'in',kind,amount,description:String(p.description||'').trim().slice(0,200)||'Crédito do professor'};if(!String(p.description||'').trim())fail('Escreva o motivo do crédito.');
        summary='Crédito de '+brl(Math.round(amount*100))+' para '+st.name;
      }else{
        const t=(dat.fine_types||[]).find(f=>f.id===Number(p.type_id)&&f.active);if(!t)fail('Escolha uma multa da lista.');
        out={student_id:st.id,type_id:t.id,reason:String(p.reason||'').trim().slice(0,150)};summary='Multa "'+t.name+'" para '+st.name;
      }
    }
    await q('INSERT INTO educa_requests(id,role,subject_id,action,payload,spend,status,summary,created_ms) VALUES(?,?,?,?,?,?,?,?,?)',[rid,role,id,action,JSON.stringify(out),spend,'esperando',summary,now()]);
    res.json({request_id:rid,status:'esperando',summary});
  }catch(e){next(e)}});
  app.get('/api/requests',auth,async(req,res,next)=>{try{
    const rows=await q("SELECT id,action,status,reason,summary,created_ms,done_ms FROM educa_requests WHERE role=? AND subject_id=? AND action NOT IN ('msgResponder','msgLer') ORDER BY created_ms DESC LIMIT 30",[req.user.role,req.user.id]);
    res.json({requests:rows.map(r=>({...r,created_ms:Number(r.created_ms),done_ms:r.done_ms?Number(r.done_ms):null}))});
  }catch(e){next(e)}});
  // O computador da escola busca os pedidos e devolve o resultado
  app.get('/api/sync/requests',syncAuth,async(req,res,next)=>{try{
    const rows=await q("SELECT id,role,subject_id,action,payload,created_ms FROM educa_requests WHERE status='esperando' ORDER BY created_ms ASC LIMIT 25",[]);
    res.json({requests:rows.map(r=>({id:r.id,role:r.role,subject_id:Number(r.subject_id),action:r.action,payload:JSON.parse(r.payload),created_ms:Number(r.created_ms)}))});
  }catch(e){next(e)}});
  app.post('/api/sync/requests/result',limit('syncres',120,60000),syncAuth,async(req,res,next)=>{try{
    let n=0;for(const r of Array.isArray(req.body?.results)?req.body.results:[]){
      if(typeof r?.id!=='string'||!['feito','nao_deu'].includes(r.status))continue;
      const u=await q("UPDATE educa_requests SET status=?,reason=?,done_ms=?,spend=0 WHERE id=? AND status='esperando' RETURNING id",[r.status,String(r.reason||'').slice(0,300),now(),r.id]);n+=u.length}
    await q('DELETE FROM educa_requests WHERE done_ms IS NOT NULL AND done_ms<?',[now()-30*86400000]);
    res.json({ok:true,updated:n});
  }catch(e){next(e)}});

  // Todo o resto que muda dados fica só na escola
  app.all('/api/*splat',(req,res)=>res.status(403).json({error:HOME_MSG}));

  const dist=distDir;
  if(dist&&fs.existsSync(dist)){app.use(express.static(dist,{maxAge:0,etag:true,setHeaders:(res,f)=>{if(f.endsWith('.html'))res.setHeader('Cache-Control','no-cache')}}));app.get('/{*path}',(req,res)=>{if(/^\/assets\//.test(req.path)||/\.[a-z0-9]{2,5}$/i.test(req.path))return res.status(404).end();res.setHeader('Cache-Control','no-cache');res.sendFile(path.join(dist,'index.html'))})}
  app.use((err,req,res,next)=>{if(err.type==='entity.too.large')return res.status(413).json({error:'Pacote grande demais.'});if(err.status)return res.status(err.status).json({error:err.message});console.error('Erro interno:',err.message);res.status(500).json({error:'Não foi possível concluir agora. Tente de novo em instantes.'})});
  return app;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const db=await openDb(process.env);
  const app=await createPortal({db,syncKey:process.env.SYNC_KEY,distDir:fileURLToPath(new URL('./dist',import.meta.url))});
  const port=Number(process.env.PORT||10000);
  app.listen(port,'0.0.0.0',()=>console.log('Portal Banco Educa ouvindo na porta '+port));
}
