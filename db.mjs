import pg from 'pg';
const toPg=sql=>{let i=0;return sql.replace(/\?/g,()=>'$'+(++i))};
export async function openDb(env=process.env){
  let q;
  if(env.PORTAL_PGLITE){
    const {PGlite}=await import('@electric-sql/pglite');
    const db=new PGlite(env.PORTAL_PGLITE==='memory'?undefined:env.PORTAL_PGLITE);
    q=async(sql,p=[])=>(await db.query(toPg(sql),p)).rows;
  }else{
    if(!env.DB_HOST||!env.DB_USER||!env.DB_PASSWORD)throw new Error('Banco de dados nao configurado (DB_HOST, DB_USER, DB_PASSWORD).');
    const pool=new pg.Pool({host:env.DB_HOST,port:Number(env.DB_PORT||5432),user:env.DB_USER,password:env.DB_PASSWORD,database:env.DB_NAME||'postgres',ssl:{rejectUnauthorized:false},max:4,idleTimeoutMillis:20000,connectionTimeoutMillis:15000});
    pool.on('error',()=>{});
    q=async(sql,p=[])=>(await pool.query(toPg(sql),p)).rows;
  }
  await q('CREATE TABLE IF NOT EXISTS educa_snap(kind TEXT NOT NULL,k TEXT NOT NULL,hash TEXT,data TEXT NOT NULL,updated_ms BIGINT,PRIMARY KEY(kind,k))');
  await q('CREATE TABLE IF NOT EXISTS educa_sessions(token_hash TEXT PRIMARY KEY,role TEXT,subject_id INTEGER,expires BIGINT)');
  await q('CREATE TABLE IF NOT EXISTS educa_attempts(k TEXT PRIMARY KEY,failures INTEGER,locked BIGINT)');
  await q('CREATE TABLE IF NOT EXISTS educa_requests(id TEXT PRIMARY KEY,role TEXT NOT NULL,subject_id INTEGER NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL,spend BIGINT DEFAULT 0,status TEXT NOT NULL,reason TEXT,summary TEXT,created_ms BIGINT NOT NULL,done_ms BIGINT)');
  await q('ALTER TABLE educa_requests ADD COLUMN IF NOT EXISTS result TEXT');
  await q('ALTER TABLE educa_attempts ALTER COLUMN failures TYPE BIGINT');
  return {q};
}
