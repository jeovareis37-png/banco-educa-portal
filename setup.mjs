// Monta a pasta dist a partir dos arquivos pub__*, enviados sem subpastas.
import fs from 'node:fs';import path from 'node:path';
fs.rmSync('dist',{recursive:true,force:true});
for(const f of fs.readdirSync('.')){if(!f.startsWith('pub__'))continue;const rel=f.slice(5).split('@').join('/');const to=path.join('dist',rel);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(f,to)}
console.log('dist pronto:',fs.readdirSync('dist').join(','));
