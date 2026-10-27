// Royal Roulette API - Cloudflare Worker + D1.
// Putaran roda dihitung dari jadwal waktu + rahasia server (tanpa timer/WebSocket): angka = HMAC(rahasia, nomor putaran).
const enc=new TextEncoder(),J=JSON.stringify;
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const rnd=(n=24)=>hex(crypto.getRandomValues(new Uint8Array(n)));
const isH=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
const normPh=s=>{let d=String(s||'').replace(/\D/g,'');if(d.startsWith('62'))d='0'+d.slice(2);return d};
const okEm=s=>/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
const REDS=new Set([1,3,5,7,9,12,14,16,18,19,21,23]);
const KEYS=new Set(['red','black','even','odd','low','high','d1','d2','d3']);
const wins=(k,n)=>{if(k[0]==='n')return +k.slice(1)===n;if(n===0)return false;return({red:REDS.has(n),black:!REDS.has(n),even:n%2===0,odd:n%2===1,low:n<=12,high:n>=13,d1:n<=8,d2:n>8&&n<=16,d3:n>16})[k]===true};
const okKey=k=>typeof k==='string'&&(KEYS.has(k)||/^n(\d|1\d|2[0-4])$/.test(k));
const okPath=p=>typeof p==='string'&&/^[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(p);
const sum=bs=>(bs||[]).reduce((s,b)=>s+b.a,0);
const SCHEMA=[
 'CREATE TABLE IF NOT EXISTS docs(path TEXT PRIMARY KEY,data TEXT NOT NULL,rev INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0,owner TEXT)',
 'CREATE INDEX IF NOT EXISTS docs_rev ON docs(rev)','CREATE INDEX IF NOT EXISTS docs_owner ON docs(owner,rev)',
 'CREATE TABLE IF NOT EXISTS sec(k TEXT PRIMARY KEY,salt TEXT NOT NULL,h TEXT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS tok(t TEXT PRIMARY KEY,r TEXT NOT NULL,id TEXT,exp INTEGER NOT NULL)',
 'CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS fl(k TEXT PRIMARY KEY,n INTEGER NOT NULL,t INTEGER NOT NULL)'];
let READY=null,HK=null;const RES=new Map();
const NEXTREV='(SELECT COALESCE(MAX(rev),0)+1 FROM docs)';
async function boot(env){
  if(READY)return READY;
  READY=(async()=>{
    const db=env.DB;await db.batch(SCHEMA.map(s=>db.prepare(s)));
    if(!(await db.prepare("SELECT 1 AS x FROM sec WHERE k='admin'").first())){const salt=rnd(8);await db.prepare('INSERT OR IGNORE INTO sec(k,salt,h) VALUES(?,?,?)').bind('admin',salt,await sha(salt+':'+await sha('rr:admin123'))).run()} // password admin awal: admin123
    await db.prepare('INSERT OR IGNORE INTO docs(path,data,rev) VALUES(?,?,'+NEXTREV+')').bind('app/cfg',J({cfg:{},pw:'*'})).run();
    await db.prepare('INSERT OR IGNORE INTO kv(k,v) VALUES(?,?)').bind('rsecret',rnd(32)).run();
    await db.prepare('INSERT OR IGNORE INTO kv(k,v) VALUES(?,?)').bind('sched',J({t0:Date.now(),startId:1,sec:30,ms:6000,rd:3,pausedAt:null,pend:null})).run();
  })();
  READY.catch(()=>{READY=null});return READY;
}
class Api{
  constructor(env){this.db=env.DB;this.env=env}
  q(sql,...b){return this.db.prepare(sql).bind(...b)}
  async kvGet(k){const r=await this.q('SELECT v FROM kv WHERE k=?',k).first();return r?r.v:null}
  async kvSet(k,v){await this.q('INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',k,v).run()}
  async getDoc(p){const r=await this.q('SELECT data,rev,deleted FROM docs WHERE path=?',p).first();return r&&!r.deleted?{d:JSON.parse(r.data),rev:r.rev}:null}
  async hasSec(k){return !!(await this.q('SELECT 1 AS x FROM sec WHERE k=?',k).first())}
  async norm(p,d){
    if(p==='app/cfg')return{...d,pw:'*'};
    if(p.startsWith('players/'))return{...d,ph:(await this.hasSec('p:'+p.slice(8)))?'*':''};
    return d;
  }
  async put(p,d,expect){
    d=await this.norm(p,d);const own=p.startsWith('players/')?p.slice(8):p.startsWith('chat/')?(d.pid||null):null;
    if(expect===undefined){await this.q('INSERT INTO docs(path,data,rev,deleted,owner) VALUES(?,?,'+NEXTREV+',0,?) ON CONFLICT(path) DO UPDATE SET data=excluded.data,rev=excluded.rev,deleted=0,owner=excluded.owner',p,J(d),own).run();return true}
    const r=await this.q('UPDATE docs SET data=?,rev='+NEXTREV+',owner=? WHERE path=? AND rev=? AND deleted=0',J(d),own,p,expect).run();return r.meta.changes===1;
  }
  async delDoc(p){await this.q("UPDATE docs SET deleted=1,data='null',rev="+NEXTREV+' WHERE path=?',p).run()}
  /* ---------- rahasia, sesi, pembatasan ---------- */
  async setSec(k,ph){const salt=rnd(8);await this.q('INSERT INTO sec(k,salt,h) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET salt=excluded.salt,h=excluded.h',k,salt,await sha(salt+':'+ph)).run()}
  async verify(k,ph){const s=await this.q('SELECT salt,h FROM sec WHERE k=?',k).first();return !!s&&(await sha(s.salt+':'+ph))===s.h}
  async mint(r,id){const t=rnd(24);await this.q('INSERT INTO tok(t,r,id,exp) VALUES(?,?,?,?)',t,r,id||null,Date.now()+(r==='a'?12*36e5:30*864e5)).run();return t}
  async auth(token){if(typeof token!=='string'||token.length<20)return{r:'x'};const r=await this.q('SELECT r,id FROM tok WHERE t=? AND exp>?',token,Date.now()).first();return r?{r:r.r,id:r.id,t:token}:{r:'x',bad:true}}
  async locked(k){const f=await this.q('SELECT n,t FROM fl WHERE k=?',k).first();if(!f)return false;if(Date.now()-f.t>6e5){await this.q('DELETE FROM fl WHERE k=?',k).run();return false}return f.n>=5}
  async fail(k){await this.q('INSERT INTO fl(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=n+1,t=excluded.t',k,Date.now()).run()}
  async okk(k){await this.q('DELETE FROM fl WHERE k=?',k).run()}
  /* ---------- pengaturan dan jadwal putaran ---------- */
  async cfgRaw(){const x=await this.getDoc('app/cfg');return x?(x.d.cfg||{}):{}}
  C(c){return{sec:Math.max(5,+c.sec||30),ms:Math.max(1000,+c.ms||6000),rd:Math.min(30,Math.max(0,c.rd===undefined?3:+c.rd||0)),paused:!!c.paused,maint:!!c.maint,
    pn:c.pn===undefined?24:+c.pn,pc:c.pc===undefined?1:+c.pc,pd:c.pd===undefined?2:+c.pd,maxb:+c.maxb||0}}
  cyc(S,now){const P=S.sec*1000+S.ms+150+S.rd*1000,e=S.pausedAt==null?now:S.pausedAt,i=Math.max(0,Math.floor((e-S.t0)/P)),start=S.t0+i*P;return{P,e,id:S.startId+i,start,close:start+S.sec*1000,rev:start+P}}
  async loadSched(now){
    let S=JSON.parse(await this.kvGet('sched')),c=this.cyc(S,now);
    if(S.pend&&c.id>S.pend.afterId){S={...S,...S.pend.p,t0:c.start,startId:c.id,pend:null};await this.kvSet('sched',J(S));c=this.cyc(S,now)}
    return{S,c};
  }
  async afterCfg(now){
    const C=this.C(await this.cfgRaw()),{S,c}=await this.loadSched(now);let ch=false;
    if(C.paused&&S.pausedAt==null){S.pausedAt=now;ch=true}
    if(!C.paused&&S.pausedAt!=null){S.t0+=now-S.pausedAt;S.pausedAt=null;ch=true}
    const same=C.sec===S.sec&&C.ms===S.ms&&C.rd===S.rd;
    if(same&&S.pend){S.pend=null;ch=true}
    else if(!same&&!(S.pend&&S.pend.p.sec===C.sec&&S.pend.p.ms===C.ms&&S.pend.p.rd===C.rd)){S.pend={afterId:c.e<c.close?c.id-1:c.id,p:{sec:C.sec,ms:C.ms,rd:C.rd}};ch=true}
    if(ch)await this.kvSet('sched',J(S));
  }
  async spinNow(now){
    const{S,c}=await this.loadSched(now);if(S.pausedAt!=null)return 'Roda sedang dijeda';if(c.e>=c.close)return 'Roda sedang berputar';
    await this.kvSet('sched',J({...S,t0:now-S.sec*1000,startId:c.id}));return null;
  }
  async rkey(){if(HK)return HK;HK=await crypto.subtle.importKey('raw',enc.encode(await this.kvGet('rsecret')),{name:'HMAC',hash:'SHA-256'},false,['sign']);return HK}
  async result(id){
    if(RES.has(id))return RES.get(id);
    const g=new Uint8Array(await crypto.subtle.sign('HMAC',await this.rkey(),enc.encode('round:'+id))),n=((g[0]<<24|g[1]<<16|g[2]<<8|g[3])>>>0)%25;
    RES.set(id,n);if(RES.size>600)RES.delete(RES.keys().next().value);return n;
  }
  async roundDoc(now){
    const{S,c}=await this.loadSched(now),sh=S.pausedAt!=null?now-S.pausedAt:0,spun=c.e>=c.close,started=spun?c.id:c.id-1,h=[];
    for(let i=started;i>=Math.max(1,started-29);i--)h.push(await this.result(i));
    const cs=started===c.id?c.start:c.start-c.P,next=spun?c.start+c.P+S.sec*1000:c.close;
    return{id:Math.max(0,started),n:started>0?h[0]:0,h,ms:S.ms,at:started>0?cs+S.sec*1000+sh:0,rev:started>0?cs+c.P+sh:0,next:next+sh};
  }
  /* ---------- penyelesaian taruhan (malas: saat pemain/admin mengakses, dan oleh cron) ---------- */
  async settlePlayer(id,now){
    for(let k=0;k<3;k++){
      const x=await this.getDoc('players/'+id);if(!x)return;const d=x.d;if(!d.bets||!d.bets.length||!d.tgt)return;
      const{c}=await this.loadSched(now);if(d.tgt>c.id-1)return;
      const C=this.C(await this.cfgRaw()),n=await this.result(d.tgt),bs=d.bets;let g=0,net=0,wg=0;
      bs.forEach(b=>{net-=b.a;wg+=b.a;if(wins(b.k,n)){const mu=b.k[0]==='n'?C.pn:b.k[0]==='d'?C.pd:C.pc,y=b.a*(mu+1);g+=y;net+=y}});
      const t='Angka '+n+': '+(net>=0?'+':'')+net.toLocaleString('id-ID')+' chip';
      if(await this.put('players/'+id,{...d,chips:d.chips+g,bets:[],tgt:0,last:bs,log:[{d:net,t}].concat(d.log||[]).slice(0,6),tw:(d.tw||0)+wg,tn:(d.tn||0)+net,seen:now},x.rev))return;
    }
  }
  async settleAll(now){
    const r=await this.q("SELECT path FROM docs WHERE deleted=0 AND path LIKE 'players/%' AND data LIKE '%\"bets\":[{%'").all();
    for(const x of r.results)await this.settlePlayer(x.path.slice(8),now);
  }
  /* ---------- visibilitas dan sinkronisasi ---------- */
  pub(a,p,d){if(a.r==='a'||p!=='app/cfg')return d;const c={...(d.cfg||{})};if(c.invite)c.invite='1';return{...d,cfg:c}}
  async sync(a,since,now){
    if(a.r==='p')await this.settlePlayer(a.id,now);else if(a.r==='a')await this.settleAll(now);
    const rows=a.r==='a'?await this.q('SELECT path,data,rev,deleted FROM docs WHERE rev>?',since).all()
      :a.r==='p'?await this.q('SELECT path,data,rev,deleted FROM docs WHERE rev>? AND (owner=? OR path=?)',since,a.id,'app/cfg').all()
      :await this.q('SELECT path,data,rev,deleted FROM docs WHERE rev>? AND path=?',since,'app/cfg').all();
    const docs={},del=[];let cursor=since;
    for(const r of rows.results){cursor=Math.max(cursor,r.rev);if(r.deleted)del.push(r.path);else docs[r.path]=this.pub(a,r.path,JSON.parse(r.data))}
    docs['game/round']=await this.roundDoc(now);
    return{ok:true,role:a.r,id:a.id||null,now,cursor,docs,del,authfail:!!a.bad};
  }
  /* ---------- aturan taruhan ---------- */
  check(old,nw,c,C){
    if(c.e>=c.close)return 'Taruhan ditutup';
    if(old.blocked||old.pending)return 'Akun tidak aktif';
    if(C.maint)return 'Mode pemeliharaan';
    const bs=nw.bets||[];
    if(!Array.isArray(bs)||bs.length>40)return 'Taruhan tidak valid';
    for(const b of bs){if(!b||!okKey(b.k)||!Number.isInteger(b.a)||b.a<=0)return 'Taruhan tidak valid';if(C.maxb&&b.a>C.maxb)return 'Melebihi batas taruhan'}
    if(bs.length&&nw.tgt!==c.id)return 'Putaran tidak cocok';
    if(!(nw.chips>=0))return 'Chip tidak cukup';
    if(nw.chips+sum(bs)!==old.chips+sum(old.bets))return 'Saldo tidak konsisten';
    return null;
  }
  async guard(a,t,p,old,nw,d,now){
    if(a.r==='a')return null;
    if(a.r==='p'){
      if(p==='players/'+a.id){
        if(t!=='upd'||!old)return 'Tidak diizinkan';
        if(!Object.keys(d).every(k=>['bets','tgt','chips','seen'].includes(k)))return 'Tidak diizinkan';
        const bc=J(old.bets||[])!==J(nw.bets||[])||old.tgt!==nw.tgt;
        if(nw.chips!==old.chips&&!bc)return 'Tidak diizinkan';
        if(!bc)return null;
        const{c}=await this.loadSched(now);return this.check(old,nw,c,this.C(await this.cfgRaw()));
      }
      if(p.startsWith('chat/')){
        if(t==='set'&&!old&&nw&&nw.pid===a.id&&nw.from==='p'&&typeof nw.text==='string'&&nw.text.length<=300)return null;
        if(t==='del'&&old&&old.pid===a.id)return null;
      }
      return 'Tidak diizinkan';
    }
    return 'Silakan masuk dulu';
  }
  /* ---------- operasi ---------- */
  async op(m,a,now){
    const cfg=await this.cfgRaw();
    switch(m.t){
      case 'reg':{
        if(cfg.reg===false)return{ok:false,e:'Pendaftaran sedang ditutup'};
        const nm=String(m.name||'').trim().slice(0,40),us=String(m.user||'').trim().toLowerCase(),em=String(m.email||'').trim().toLowerCase(),ph=normPh(m.phone);
        if(nm.length<2||!/^[a-z0-9_.]{3,16}$/.test(us)||!okEm(em)||ph.length<9||ph.length>15||!isH(m.ph))return{ok:false,e:'Data pendaftaran tidak valid'};
        if(cfg.invite&&String(m.code||'').trim()!==cfg.invite)return{ok:false,e:'Kode undangan salah'};
        const pl=(await this.q("SELECT data FROM docs WHERE deleted=0 AND path LIKE 'players/%'").all()).results.map(r=>JSON.parse(r.data));
        if(+cfg.maxp&&pl.length>=+cfg.maxp)return{ok:false,e:'Kuota pemain sudah penuh'};
        if(pl.some(d=>(d.user||d.name||'').toLowerCase()===us))return{ok:false,e:'Username sudah dipakai'};
        if(pl.some(d=>d.email===em))return{ok:false,e:'Email sudah terdaftar'};
        const id=Date.now().toString(36)+rnd(2),pending=!!cfg.appr;
        await this.setSec('p:'+id,m.ph);
        await this.put('players/'+id,{name:nm,user:us,phone:ph,email:em,chips:cfg.start===undefined?1000:Math.max(0,+cfg.start||0),bets:[],tgt:0,log:[],last:[],created:now,seen:now,blocked:false,pending,tw:0,tn:0,contact:'',note:''});
        await this.put('logs/'+rnd(4),{t:now,m:'Pendaftaran baru: '+nm+' (@'+us+')'+(pending?' - menunggu persetujuan':'')});
        if(pending)return{ok:true,pending:true};
        return{ok:true,pid:id,token:await this.mint('p',id)};
      }
      case 'login':{
        const u=String(m.u||'').trim().toLowerCase();if(!u||!isH(m.ph))return{ok:false,e:'Data tidak valid'};
        const key='l:'+u;if(await this.locked(key))return{ok:false,e:'Terlalu banyak percobaan. Coba lagi 10 menit lagi.'};
        const rows=(await this.q("SELECT path,data FROM docs WHERE deleted=0 AND path LIKE 'players/%'").all()).results;
        const e=rows.map(r=>[r.path,JSON.parse(r.data)]).find(([,d])=>(d.user||d.name||'').toLowerCase()===u||d.email===u);
        if(!e||!(await this.verify('p:'+e[0].slice(8),m.ph))){await this.fail(key);return{ok:false,e:'Username atau password salah'}}
        const[path,d]=e,id=path.slice(8);
        if(d.blocked)return{ok:false,e:'Akun diblokir. Hubungi admin.'};
        if(d.pending)return{ok:false,e:'Akun Anda menunggu persetujuan admin.'};
        await this.okk(key);await this.put(path,{...d,seen:now});
        return{ok:true,pid:id,token:await this.mint('p',id)};
      }
      case 'reset':{
        const em=String(m.email||'').trim().toLowerCase(),ph=normPh(m.phone);if(!okEm(em)||ph.length<9||!isH(m.ph))return{ok:false,e:'Data tidak valid'};
        const key='r:'+em;if(await this.locked(key))return{ok:false,e:'Terlalu banyak percobaan. Coba lagi nanti.'};
        const rows=(await this.q("SELECT path,data FROM docs WHERE deleted=0 AND path LIKE 'players/%'").all()).results;
        const e=rows.map(r=>[r.path,JSON.parse(r.data)]).find(([,d])=>d.email===em&&normPh(d.phone)===ph);
        if(!e){await this.fail(key);return{ok:false,e:'Email atau nomor telepon tidak cocok'}}
        if(e[1].blocked)return{ok:false,e:'Akun diblokir. Hubungi admin.'};
        await this.okk(key);const id=e[0].slice(8);await this.setSec('p:'+id,m.ph);await this.put(e[0],e[1]);await this.q("DELETE FROM tok WHERE r='p' AND id=?",id).run();return{ok:true};
      }
      case 'profile':{
        const x=a.r==='p'?await this.getDoc('players/'+a.id):null;if(!x)return{ok:false,e:'Silakan masuk dulu'};
        const nm=String(m.name||'').trim().slice(0,40),em=String(m.email||'').trim().toLowerCase(),ph=normPh(m.phone);
        if(nm.length<2||!okEm(em)||ph.length<9||ph.length>15)return{ok:false,e:'Data profil tidak valid'};
        const rows=(await this.q("SELECT path,data FROM docs WHERE deleted=0 AND path LIKE 'players/%'").all()).results;
        if(rows.some(r=>r.path!=='players/'+a.id&&JSON.parse(r.data).email===em))return{ok:false,e:'Email sudah dipakai akun lain'};
        await this.put('players/'+a.id,{...x.d,name:nm,email:em,phone:ph});return{ok:true};
      }
      case 'chpw':{
        if(a.r!=='p'||!isH(m.old)||!isH(m.ph))return{ok:false,e:'Data tidak valid'};
        const key='c:'+a.id;if(await this.locked(key))return{ok:false,e:'Terlalu banyak percobaan'};
        if(!(await this.verify('p:'+a.id,m.old))){await this.fail(key);return{ok:false,e:'Password lama salah'}}
        await this.okk(key);await this.setSec('p:'+a.id,m.ph);await this.q("DELETE FROM tok WHERE r='p' AND id=? AND t<>?",a.id,a.t).run();return{ok:true};
      }
      case 'logout':{if(typeof m.token==='string')await this.q('DELETE FROM tok WHERE t=?',m.token).run();return{ok:true}}
      case 'alogin':{
        if(!isH(m.ph))return{ok:false,e:'Data tidak valid'};if(await this.locked('a'))return{ok:false,e:'Terlalu banyak percobaan. Coba lagi nanti.'};
        if(!(await this.verify('admin',m.ph))){await this.fail('a');return{ok:false,e:'Password salah'}}
        await this.okk('a');return{ok:true,token:await this.mint('a')};
      }
      case 'achpw':{
        if(a.r!=='a'||!isH(m.old)||!isH(m.ph))return{ok:false,e:'Data tidak valid'};
        if(!(await this.verify('admin',m.old)))return{ok:false,e:'Password lama salah'};
        await this.setSec('admin',m.ph);await this.q("DELETE FROM tok WHERE r='a'").run();return{ok:true,token:await this.mint('a')};
      }
      case 'setpw':{
        if(a.r!=='a'||!isH(m.ph)||!okPath('players/'+m.pid))return{ok:false,e:'Data tidak valid'};
        const x=await this.getDoc('players/'+m.pid);if(!x)return{ok:false,e:'Akun tidak ada'};
        await this.setSec('p:'+m.pid,m.ph);await this.put('players/'+m.pid,x.d);await this.q("DELETE FROM tok WHERE r='p' AND id=?",m.pid).run();return{ok:true};
      }
      case 'revoke':{if(a.r!=='a')return{ok:false,e:'Khusus admin'};await this.q("DELETE FROM tok WHERE r='p'").run();return{ok:true}}
      case 'spin':{if(a.r!=='a')return{ok:false,e:'Khusus admin'};const e=await this.spinNow(now);return e?{ok:false,e}:{ok:true}}
    }
    return null;
  }
  async generic(m,a,now){
    if(!okPath(m.p))return{ok:false,e:'path tidak valid'};
    if(m.p.startsWith('game/'))return{ok:false,e:'dikelola server'};
    if(a.r==='p'&&m.p==='players/'+a.id)await this.settlePlayer(a.id,now);
    if(m.t==='del'){
      const old=await this.getDoc(m.p),err=await this.guard(a,'del',m.p,old&&old.d,null,null,now);if(err)return{ok:false,e:err};
      if(m.p.startsWith('players/')){const id=m.p.slice(8);await this.q('DELETE FROM sec WHERE k=?','p:'+id).run();await this.q("DELETE FROM tok WHERE r='p' AND id=?",id).run()}
      if(old)await this.delDoc(m.p);return{ok:true};
    }
    if((m.t==='set'||m.t==='upd')&&m.d&&typeof m.d==='object'){
      for(let k=0;k<4;k++){
        const old=await this.getDoc(m.p);if(m.t==='upd'&&!old)return{ok:false,e:'dokumen tidak ada'};
        const nw=m.t==='upd'?{...old.d,...m.d}:m.d,err=await this.guard(a,m.t,m.p,old&&old.d,nw,m.d,now);if(err)return{ok:false,e:err};
        const done=m.t==='upd'?await this.put(m.p,nw,old.rev):await this.put(m.p,nw);
        if(done){if(m.p==='app/cfg')await this.afterCfg(now);return{ok:true}}
      }
      return{ok:false,e:'Terjadi bentrok data, coba lagi'};
    }
    return{ok:false,e:'perintah tidak dikenal'};
  }
}
const cors=env=>({'Access-Control-Allow-Origin':(env.ORIGIN||'*'),'Access-Control-Allow-Methods':'POST,GET,OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'86400','Vary':'Origin'});
const out=(env,o,s=200)=>new Response(J(o),{status:s,headers:{'Content-Type':'application/json','Cache-Control':'no-store',...cors(env)}});
export default{
  async fetch(req,env){
    const u=new URL(req.url);
    if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors(env)});
    if(u.pathname==='/api/health')return out(env,{ok:true});
    if(req.method!=='POST'||(u.pathname!=='/api/sync'&&u.pathname!=='/api/op'))return out(env,{ok:false,e:'Tidak ditemukan'},404);
    try{
      await boot(env);const api=new Api(env),now=Date.now();let m;try{m=await req.json()}catch(e){return out(env,{ok:false,e:'JSON tidak valid'},400)}
      const a=await api.auth(m.token);
      if(u.pathname==='/api/sync')return out(env,await api.sync(a,+m.since||0,now));
      return out(env,(await api.op(m,a,now))||(await api.generic(m,a,now)));
    }catch(e){return out(env,{ok:false,e:'Galat server'},500)}
  },
  async scheduled(ev,env,ctx){ctx.waitUntil((async()=>{await boot(env);await new Api(env).settleAll(Date.now())})())}
};
