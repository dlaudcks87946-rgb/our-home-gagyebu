const express=require("express"),{Pool}=require("pg"),crypto=require("crypto"),path=require("path");
const {DATABASE_URL,APP_PASSWORD,SESSION_SECRET,PORT=3000}=process.env;
if(!DATABASE_URL||!APP_PASSWORD||!SESSION_SECRET){console.error("DATABASE_URL, APP_PASSWORD, SESSION_SECRET 환경변수가 필요합니다.");process.exit(1)}
const pool=new Pool({connectionString:DATABASE_URL});
const app=express();app.set("trust proxy",1);app.disable("x-powered-by");
app.use(express.json({limit:"1mb"}));
app.use((q,s,n)=>{s.set({"X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex","Cache-Control":"no-store","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY"});n()});
const hash=v=>crypto.createHash("sha256").update(v).digest(),pwHash=hash(APP_PASSWORD);
const sign=v=>crypto.createHmac("sha256",SESSION_SECRET).update(v).digest("hex");
const valid=t=>{if(!t)return false;const[i,sig]=t.split(".");if(!sig||!(+i>Date.now()))return false;const a=Buffer.from(sig),b=Buffer.from(sign(i));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const auth=(q,s,n)=>{const m=/(?:^|; )sid=([^;]+)/.exec(q.headers.cookie||"");valid(m&&m[1])?n():s.status(401).json({error:"auth"})};
const fails=new Map();
app.post("/api/login",(q,s)=>{const f=fails.get(q.ip)||{n:0,t:Date.now()};if(Date.now()-f.t>9e5){f.n=0;f.t=Date.now()}
if(f.n>=10)return s.status(429).json({error:"too many"});
const pw=q.body&&typeof q.body.password==="string"?q.body.password:"";
if(!crypto.timingSafeEqual(hash(pw),pwHash)){f.n++;fails.set(q.ip,f);return s.status(401).json({error:"bad"})}
fails.delete(q.ip);const exp=Date.now()+90*864e5;
s.cookie("sid",exp+"."+sign(String(exp)),{httpOnly:true,sameSite:"lax",secure:q.secure,maxAge:90*864e5});s.json({ok:true})});
app.post("/api/logout",(q,s)=>{s.clearCookie("sid");s.json({ok:true})});
app.get("/api/state",auth,async(q,s)=>{try{
const e=await pool.query("SELECT data FROM entries ORDER BY id"),st=await pool.query("SELECT data FROM settings WHERE id=1");
s.json({data:e.rows.map(r=>r.data),settings:st.rows[0]?st.rows[0].data:null})}catch(err){console.error(err);s.status(500).json({error:"db"})}});
const okEntry=x=>x&&Number.isSafeInteger(x.id)&&x.id>0&&typeof x.d==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(x.d)&&Number.isSafeInteger(x.a)&&x.a>0&&(x.t==="수입"||x.t==="지출")&&typeof x.c==="string";
app.post("/api/sync",auth,async(q,s)=>{const up=Array.isArray(q.body.upsert)?q.body.upsert:[],rm=Array.isArray(q.body.remove)?q.body.remove:[];
if(up.length>2000||rm.length>2000||!up.every(okEntry)||!rm.every(Number.isSafeInteger))return s.status(400).json({error:"invalid"});
const c=await pool.connect();try{await c.query("BEGIN");
for(const x of up)await c.query("INSERT INTO entries(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2",[x.id,x]);
if(rm.length)await c.query("DELETE FROM entries WHERE id=ANY($1::bigint[])",[rm]);
await c.query("COMMIT");s.json({ok:true})}catch(err){await c.query("ROLLBACK").catch(()=>{});console.error(err);s.status(500).json({error:"db"})}finally{c.release()}});
app.put("/api/settings",auth,async(q,s)=>{const b=q.body;if(!b||!Array.isArray(b.fixed))return s.status(400).json({error:"invalid"});
try{await pool.query("INSERT INTO settings(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1",[b]);s.json({ok:true})}catch(err){console.error(err);s.status(500).json({error:"db"})}});
app.use(express.static(path.join(__dirname,"public")));
(async()=>{await pool.query("CREATE TABLE IF NOT EXISTS entries(id BIGINT PRIMARY KEY,data JSONB NOT NULL)");
await pool.query("CREATE TABLE IF NOT EXISTS settings(id INT PRIMARY KEY,data JSONB NOT NULL)");
app.listen(PORT,"0.0.0.0",()=>console.log("listening "+PORT))})().catch(e=>{console.error(e);process.exit(1)});
