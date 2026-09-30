const express=require("express"),cookieParser=require("cookie-parser"),crypto=require("crypto"),path=require("path");
const {promisify}=require("util"),scrypt=promisify(crypto.scrypt);
const pg=require("pg");pg.types.setTypeParser(20,Number);
const {ADMIN_PASSWORD,SESSION_SECRET}=process.env;
const DB_URL=(process.env.DATABASE_URL||process.env.POSTGRES_URL||"").trim();
let CONFIG_ERR=null;
if(!ADMIN_PASSWORD||!SESSION_SECRET||SESSION_SECRET.length<32) CONFIG_ERR="Server not configured: set ADMIN_PASSWORD and a SESSION_SECRET of 32+ characters in Vercel, then redeploy.";
else if(!DB_URL) CONFIG_ERR="Server not configured: DATABASE_URL is missing. In Vercel open the Storage tab, create a Neon database and connect it to this project, then redeploy.";
const SECURE=process.env.NODE_ENV==="production"||!!process.env.VERCEL;
const pool=CONFIG_ERR?null:new pg.Pool({connectionString:DB_URL,max:3,idleTimeoutMillis:10000,ssl:/localhost|127\.0\.0\.1/.test(DB_URL)?false:{rejectUnauthorized:false}});
const toPg=t=>{let i=0;return t.replace(/\?/g,()=>"$"+(++i))};
const q=async(sql,args=[])=>(await pool.query(toPg(sql),args)).rows;
const one=async(sql,args)=>(await q(sql,args))[0];

// ---- schema (ballots are anonymous: votes carry no voter_id or timestamp) ----
const SCHEMA=[
 "CREATE TABLE IF NOT EXISTS voters(id SERIAL PRIMARY KEY,student_id TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,has_voted INTEGER NOT NULL DEFAULT 0)",
 "CREATE TABLE IF NOT EXISTS positions(id SERIAL PRIMARY KEY,name TEXT NOT NULL,max_choices INTEGER NOT NULL DEFAULT 1,sort_order BIGINT NOT NULL DEFAULT 0)",
 "CREATE TABLE IF NOT EXISTS candidates(id SERIAL PRIMARY KEY,position_id INTEGER NOT NULL REFERENCES positions(id) ON DELETE CASCADE,name TEXT NOT NULL,bio TEXT DEFAULT '',photo_url TEXT DEFAULT '')",
 "CREATE TABLE IF NOT EXISTS votes(id SERIAL PRIMARY KEY,position_id INTEGER NOT NULL,candidate_id INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
 "CREATE TABLE IF NOT EXISTS audit_logs(id SERIAL PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now())",
 "CREATE TABLE IF NOT EXISTS attempts(k TEXT PRIMARY KEY,n INTEGER NOT NULL,reset_at BIGINT NOT NULL)",
 "INSERT INTO settings VALUES('election_open','0'),('results_published','0') ON CONFLICT DO NOTHING"
];
const ready=CONFIG_ERR?Promise.resolve():(async()=>{
 const c=await pool.connect();
 try{
  await c.query("BEGIN");await c.query("SELECT pg_advisory_xact_lock(7342)");
  for(const t of SCHEMA)await c.query(t);
  await c.query("INSERT INTO settings VALUES('school_name',$1) ON CONFLICT DO NOTHING",[process.env.SCHOOL_NAME||"School Election"]);
  await c.query("COMMIT");
 }catch(e){await c.query("ROLLBACK").catch(()=>{});throw e}finally{c.release()}
})();
ready.catch(e=>console.error("DB init failed:",e.message));

const getS=async k=>(await one("SELECT value FROM settings WHERE key=?",[k]))?.value;
const setS=(k,v)=>q("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[k,String(v)]);
const audit=(a,b)=>q("INSERT INTO audit_logs(actor,action) VALUES(?,?)",[a,b]);

// ---- crypto ----
async function hashPw(p){const s=crypto.randomBytes(16).toString("hex");return s+":"+(await scrypt(p,s,64)).toString("hex")}
async function checkPw(p,stored){const [s,h]=stored.split(":");if(!h)return false;return crypto.timingSafeEqual(await scrypt(p,s,64),Buffer.from(h,"hex"))}
const sha=x=>crypto.createHash("sha256").update(x).digest();
const safeEq=(a,b)=>crypto.timingSafeEqual(sha(a),sha(b));
const mac=v=>crypto.createHmac("sha256",SESSION_SECRET).update(v).digest("hex");
const sign=(kind,id,ttl=8*3600e3)=>{const v=`${kind}:${id}:${Date.now()+ttl}`;return v+"."+mac(v)};
function verify(tok,kind){
 const i=String(tok||"").lastIndexOf(".");if(i<0)return null;
 const v=tok.slice(0,i),sig=tok.slice(i+1),exp=mac(v);
 if(sig.length!==exp.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(exp)))return null;
 const [k,id,e]=v.split(":");return k===kind&&Number(e)>Date.now()?id:null;
}
const cookieOpts={httpOnly:true,sameSite:"strict",secure:SECURE,maxAge:8*3600e3};
const isAdmin=req=>verify(req.cookies.admin_session,"admin")!==null;

// ---- brute-force throttle (DB-backed, so it works across serverless instances) ----
async function blocked(k){const r=await one("SELECT n,reset_at FROM attempts WHERE k=?",[k]);return r&&r.reset_at>Date.now()&&r.n>=5}
async function fail(k){await q("INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN reset_at<? THEN 1 ELSE n+1 END,reset_at=CASE WHEN reset_at<? THEN ? ELSE reset_at END",[k,Date.now()+9e5,Date.now(),Date.now(),Date.now()+9e5])}
const clear=k=>q("DELETE FROM attempts WHERE k=?",[k]);

const app=express();
app.disable("x-powered-by");
app.set("trust proxy",1);
app.use((req,res,next)=>{
 res.set({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store"});
 next();
});
app.use(express.json({limit:"500kb"}));
app.use(cookieParser());
if(!process.env.VERCEL) app.use(express.static(path.join(__dirname,"..","public")));
app.use("/api",(req,res,next)=>{
 if(CONFIG_ERR)return res.status(500).json({error:CONFIG_ERR});
 // CSRF defence on top of SameSite=Strict: state-changing calls must be JSON
 if(req.method==="POST"&&!req.is("application/json"))return res.status(415).json({error:"JSON required"});
 ready.then(()=>next(),next);
});
const h=fn=>(req,res,next)=>fn(req,res,next).catch(e=>{console.error(e);res.status(500).json({error:"Server error"})});
const adminOnly=(req,res,next)=>isAdmin(req)?next():res.status(401).json({error:"Admin authentication required"});
const voterOf=async req=>{const id=verify(req.cookies.voter_session,"voter");return id?await one("SELECT id,student_id,name,has_voted FROM voters WHERE id=?",[Number(id)]):null};
const pct=(a,b)=>b?Math.round(a*1000/b)/10:0;

// ---- public ----
app.get("/api/config",h(async(req,res)=>res.json({school_name:await getS("school_name"),election_open:await getS("election_open")==="1",results_published:await getS("results_published")==="1"})));

app.post("/api/login",h(async(req,res)=>{
 const sid=String(req.body?.student_id||"").trim().slice(0,64),k="v:"+req.ip+":"+sid;
 if(await blocked(k))return res.status(429).json({error:"Too many attempts. Try again in 15 minutes."});
 const row=await one("SELECT * FROM voters WHERE student_id=?",[sid]);
 const ok=row&&await checkPw(String(req.body?.password||""),row.password_hash);
 if(!ok){await fail(k);return res.status(401).json({error:"Invalid student ID or password"})}
 await clear(k);
 res.cookie("voter_session",sign("voter",row.id),cookieOpts);
 res.json({name:row.name,student_id:row.student_id,has_voted:!!row.has_voted});
}));
app.post("/api/logout",(req,res)=>{res.clearCookie("voter_session");res.clearCookie("admin_session");res.json({ok:true})});

app.get("/api/ballot",h(async(req,res)=>{
 const v=await voterOf(req);
 if(!v)return res.status(401).json({error:"Login required"});
 if(await getS("election_open")!=="1")return res.status(403).json({error:"The election is currently closed"});
 if(v.has_voted)return res.status(409).json({error:"You have already voted"});
 const [ps,cs]=await Promise.all([q("SELECT * FROM positions ORDER BY sort_order,id"),q("SELECT id,position_id,name,bio,photo_url FROM candidates ORDER BY id")]);
 res.json({voter:v,positions:ps.map(p=>({...p,candidates:cs.filter(c=>c.position_id===p.id)}))});
}));

app.post("/api/vote",h(async(req,res)=>{
 const v=await voterOf(req);
 if(!v)return res.status(401).json({error:"Login required"});
 if(await getS("election_open")!=="1")return res.status(403).json({error:"Election is closed"});
 const sel=req.body?.selections;
 if(!sel||typeof sel!=="object")return res.status(400).json({error:"Invalid ballot"});
 const [ps,cs]=await Promise.all([q("SELECT id,max_choices FROM positions"),q("SELECT id,position_id FROM candidates")]);
 const rows=[];
 for(const p of ps){
  const ids=Array.isArray(sel[p.id])?sel[p.id].map(Number):[];
  if(new Set(ids).size!==ids.length||ids.length!==p.max_choices)return res.status(400).json({error:`Select exactly ${p.max_choices} different candidate(s) for every position`});
  for(const c of ids){if(!cs.some(x=>x.id===c&&x.position_id===p.id))return res.status(400).json({error:"Invalid candidate selection"});rows.push([p.id,c])}
 }
 if(!ps.length)return res.status(400).json({error:"No positions configured"});
 const cl=await pool.connect();
 try{
  await cl.query("BEGIN");
  // atomic claim: only one concurrent request can flip has_voted 0 -> 1
  const u=await cl.query("UPDATE voters SET has_voted=1 WHERE id=$1 AND has_voted=0",[v.id]);
  if(!u.rowCount){await cl.query("ROLLBACK");return res.status(409).json({error:"This voter has already submitted a ballot"})}
  for(const r of rows)await cl.query("INSERT INTO votes(position_id,candidate_id) VALUES($1,$2)",r);
  await cl.query("INSERT INTO audit_logs(actor,action) VALUES($1,$2)",["voter:"+v.student_id,"Ballot submitted"]);
  await cl.query("COMMIT");res.json({ok:true});
 }catch(e){await cl.query("ROLLBACK").catch(()=>{});throw e}finally{cl.release()}
}));

async function results(){
 const [ps,cs,total,voted]=await Promise.all([
  q("SELECT * FROM positions ORDER BY sort_order,id"),
  q("SELECT c.id,c.position_id,c.name,COUNT(v.id) votes FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id GROUP BY c.id ORDER BY votes DESC,c.name"),
  one("SELECT COUNT(*) n FROM voters"),one("SELECT COUNT(*) n FROM voters WHERE has_voted=1")]);
 return {results:ps.map(p=>({...p,candidates:cs.filter(c=>c.position_id===p.id)})),total:total.n,voted:voted.n,turnout:pct(voted.n,total.n)};
}
app.get("/api/results",h(async(req,res)=>{
 const open=await getS("election_open")==="1";
 if(!isAdmin(req)&&(open||await getS("results_published")!=="1"))return res.status(403).json({error:"Results are not published"});
 res.json(await results());
}));

// ---- admin ----
app.post("/api/admin/login",h(async(req,res)=>{
 const k="a:"+req.ip;
 if(await blocked(k))return res.status(429).json({error:"Too many attempts. Try again in 15 minutes."});
 if(!safeEq(String(req.body?.password||""),ADMIN_PASSWORD)){await fail(k);return res.status(401).json({error:"Invalid admin password"})}
 await clear(k);res.cookie("admin_session",sign("admin",1),cookieOpts);await audit("admin","Admin login");res.json({ok:true});
}));
app.get("/api/admin/summary",adminOnly,h(async(req,res)=>{
 const c=async t=>(await one(`SELECT COUNT(*) n FROM ${t}`)).n;
 const voters=await c("voters"),voted=(await one("SELECT COUNT(*) n FROM voters WHERE has_voted=1")).n;
 res.json({school_name:await getS("school_name"),election_open:await getS("election_open")==="1",results_published:await getS("results_published")==="1",voters,voted,candidates:await c("candidates"),positions:await c("positions"),turnout:pct(voted,voters)});
}));
const locked=async()=>await getS("election_open")==="1"||(await one("SELECT COUNT(*) n FROM votes")).n>0;
app.post("/api/admin/settings",adminOnly,h(async(req,res)=>{
 const b=req.body||{};
 if("election_open" in b){
  if(b.election_open){const n=await one("SELECT (SELECT COUNT(*) FROM positions) p,(SELECT COUNT(*) FROM candidates) c");if(!n.p||!n.c)return res.status(400).json({error:"Add positions and candidates first"})}
  await setS("election_open",b.election_open?"1":"0");
  if(b.election_open)await setS("results_published","0");
 }
 if("results_published" in b){
  if(b.results_published&&await getS("election_open")==="1")return res.status(400).json({error:"Close the election before publishing results"});
  await setS("results_published",b.results_published?"1":"0");
 }
 if(String(b.school_name||"").trim())await setS("school_name",String(b.school_name).trim().slice(0,120));
 await audit("admin","Settings updated: "+Object.keys(b).join(","));res.json({ok:true});
}));
app.post("/api/admin/position",adminOnly,h(async(req,res)=>{
 if(await locked())return res.status(409).json({error:"Ballot is locked once voting has started"});
 const name=String(req.body?.name||"").trim().slice(0,120),max=Number(req.body?.max_choices||1);
 if(!name||!Number.isInteger(max)||max<1||max>10)return res.status(400).json({error:"Invalid position"});
 const r=await one("INSERT INTO positions(name,max_choices,sort_order) VALUES(?,?,?) RETURNING id",[name,max,Date.now()]);
 await audit("admin","Position created: "+name);res.json({id:r.id});
}));
app.post("/api/admin/candidate",adminOnly,h(async(req,res)=>{
 if(await locked())return res.status(409).json({error:"Ballot is locked once voting has started"});
 const name=String(req.body?.name||"").trim().slice(0,120),pos=Number(req.body?.position_id),photo=String(req.body?.photo_url||"").trim();
 if(!name||!Number.isInteger(pos)||!await one("SELECT id FROM positions WHERE id=?",[pos]))return res.status(400).json({error:"Invalid candidate"});
 if(photo&&!/^https:\/\//i.test(photo))return res.status(400).json({error:"Photo URL must start with https://"});
 const r=await one("INSERT INTO candidates(position_id,name,bio,photo_url) VALUES(?,?,?,?) RETURNING id",[pos,name,String(req.body.bio||"").slice(0,1000),photo]);
 await audit("admin","Candidate created: "+name);res.json({id:r.id});
}));
app.delete("/api/admin/candidate/:id",adminOnly,h(async(req,res)=>{
 if(await locked())return res.status(409).json({error:"Ballot is locked once voting has started"});
 await q("DELETE FROM candidates WHERE id=?",[Number(req.params.id)||0]);await audit("admin","Candidate deleted: "+req.params.id);res.json({ok:true});
}));
app.delete("/api/admin/position/:id",adminOnly,h(async(req,res)=>{
 if(await locked())return res.status(409).json({error:"Ballot is locked once voting has started"});
 await q("DELETE FROM candidates WHERE position_id=?",[Number(req.params.id)||0]);await q("DELETE FROM positions WHERE id=?",[Number(req.params.id)||0]);
 await audit("admin","Position deleted: "+req.params.id);res.json({ok:true});
}));
// single voter: {student_id,name,password}  |  bulk: {voters:[{student_id,name,password}, ...]} (max 2000)
app.post("/api/admin/voter",adminOnly,h(async(req,res)=>{
 const list=Array.isArray(req.body?.voters)?req.body.voters.slice(0,2000):[req.body||{}];
 let added=0;const skipped=[];
 for(const x of list){
  const sid=String(x.student_id||"").trim().slice(0,64),name=String(x.name||"").trim().slice(0,120),pw=String(x.password||"");
  if(!sid||!name||pw.length<6){skipped.push(sid||"?");continue}
  try{await q("INSERT INTO voters(student_id,name,password_hash) VALUES(?,?,?)",[sid,name,await hashPw(pw)]);added++}catch{skipped.push(sid)}
 }
 await audit("admin",`Voters created: ${added}`);
 if(!Array.isArray(req.body?.voters)&&!added)return res.status(409).json({error:"Invalid details or Student ID already exists"});
 res.json({ok:true,added,skipped});
}));
app.post("/api/admin/voter/reset",adminOnly,h(async(req,res)=>{
 const pw=String(req.body?.password||"");if(pw.length<6)return res.status(400).json({error:"6+ character password required"});
 const r=await pool.query("UPDATE voters SET password_hash=$1 WHERE student_id=$2",[await hashPw(pw),String(req.body?.student_id||"").trim()]);
 if(!r.rowCount)return res.status(404).json({error:"Voter not found"});
 await audit("admin","Password reset: "+req.body.student_id);res.json({ok:true});
}));
app.get("/api/admin/data",adminOnly,h(async(req,res)=>res.json({
 positions:await q("SELECT * FROM positions ORDER BY sort_order,id"),
 candidates:await q("SELECT * FROM candidates ORDER BY position_id,id"),
 logs:await q("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
})));

app.use("/api",(req,res)=>res.status(404).json({error:"Not found"}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Database connection failed. Check that the Neon database is connected to this Vercel project (DATABASE_URL), then redeploy."})});
module.exports=app;
if(require.main===module){const P=process.env.PORT||3000;app.listen(P,()=>console.log(`Running on http://localhost:${P}`))}
