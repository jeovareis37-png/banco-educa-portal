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
    if(p.role==='admin')fail('O gerente entra só no computador da escola.',403);
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
    res.json({...s.data,home:{online:true,updated_at:sync?.data?.updated_at||null,received_ms:sync?.updated_ms||null}});
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

  // Tudo que muda dados fica só na escola
  app.all('/api/*splat',(req,res)=>res.status(403).json({error:HOME_MSG}));

  const dist=distDir;
  if(dist&&fs.existsSync(dist)){app.use(express.static(dist,{maxAge:'1h'}));app.get('/{*path}',(req,res)=>res.sendFile(path.join(dist,'index.html')))}
  app.use((err,req,res,next)=>{if(err.type==='entity.too.large')return res.status(413).json({error:'Pacote grande demais.'});if(err.status)return res.status(err.status).json({error:err.message});console.error('Erro interno:',err.message);res.status(500).json({error:'Não foi possível concluir agora. Tente de novo em instantes.'})});
  return app;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const db=await openDb(process.env);
  const app=await createPortal({db,syncKey:process.env.SYNC_KEY,distDir:fileURLToPath(new URL('./dist',import.meta.url))});
  const port=Number(process.env.PORT||10000);
  app.listen(port,'0.0.0.0',()=>console.log('Portal Banco Educa ouvindo na porta '+port));
}
