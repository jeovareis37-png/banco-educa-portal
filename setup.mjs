// Monta a pasta dist a partir dos arquivos pub__* (enviados sem subpastas; arquivos grandes vem em partes gz64).
import fs from 'node:fs';import path from 'node:path';import zlib from 'node:zlib';
fs.rmSync('dist',{recursive:true,force:true});
const out=(rel,buf)=>{const to=path.join('dist',rel.split('@').join('/'));fs.mkdirSync(path.dirname(to),{recursive:true});fs.writeFileSync(to,buf)};
const big={};
for(const f of fs.readdirSync('.').sort()){
  if(!f.startsWith('pub__'))continue;
  const m=f.slice(5).match(/^(.*)\.gz64\.(\d+)$/);
  if(m){(big[m[1]]=big[m[1]]||[]).push(fs.readFileSync(f,'utf8'));continue}
  out(f.slice(5),fs.readFileSync(f));
}
for(const [rel,parts] of Object.entries(big))out(rel,zlib.gunzipSync(Buffer.from(parts.join(''),'base64')));
console.log('dist pronto:',fs.readdirSync('dist').join(','));
