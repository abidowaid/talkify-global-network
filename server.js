'use strict';
require('dotenv').config();
const express=require('express');
const helmet=require('helmet');
const cors=require('cors');
const session=require('express-session');
const PgSession=require('connect-pg-simple')(session);
const rateLimit=require('express-rate-limit');
const bcrypt=require('bcryptjs');
const {Pool}=require('pg');
const crypto=require('crypto');

const app=express();
const PORT=Number(process.env.PORT||3000);
const DATABASE_URL=process.env.DATABASE_URL;

if(!DATABASE_URL) console.warn('DATABASE_URL is not set. Set it in Render Environment before deployment.');

const pool=new Pool({
  connectionString:DATABASE_URL,
  ssl:process.env.PGSSLMODE==='disable'?false:{rejectUnauthorized:false},
  max:10,
  connectionTimeoutMillis:10000,
  idleTimeoutMillis:30000
});

const FEATURES=[
[1,'Master Admin Login & Security','Security'],
[2,'Main Dashboard','Overview'],
[3,'User Management','Users'],
[4,'KYC Management','Users'],
[5,'Wallet / Balance Management','Finance'],
[6,'Payment Gateway Management','Finance'],
[7,'Recharge Management','Finance'],
[8,'Balance Transfer Management','Finance'],
[9,'Calling Management','Calling'],
[10,'Call Rates & Revenue','Calling'],
[11,'Country Management','Global'],
[12,'SMS Management','Messaging'],
[13,'User Inbox Message','Messaging'],
[14,'Admin Notice Popup','Messaging'],
[15,'Support / Help Center','Support'],
[16,'Multilingual Support','Support'],
[17,'Live Agent System','Support'],
[18,'Central Support Inbox + Claim System','Support'],
[19,'Payment Problem Automatic Support','Support'],
[20,'Agent User Profile','Support'],
[21,'Agent Action Panel','Support'],
[22,'Promo / Referral System','Growth'],
[23,'Referral Fraud Protection','Growth'],
[24,'Global Analytics','Reports'],
[25,'Reports & Export','Reports'],
[26,'Audit Log','Security'],
[27,'Sub-Admin Management — Master Admin','Sub-Admins'],
[28,'Sub-Admin Identity Enrollment','Sub-Admins'],
[29,'Sub-Admin Activity & Performance','Sub-Admins'],
[30,'Sub-Admin Permission System','Sub-Admins'],
[31,'Sub-Admin → Master Admin Help','Sub-Admins'],
[32,'Sub-Admin Face Login','Sub-Admins'],
[33,'Sub-Admin Dashboard','Sub-Admins'],
[34,'Sub-Admin Support Inbox','Sub-Admins'],
[35,'Sub-Admin Master Help','Sub-Admins'],
[36,'Sub-Admin Restrictions','Sub-Admins'],
[37,'Notification Center','Messaging'],
[38,'Real-time Notification','Messaging'],
[39,'Admin Search','Tools'],
[40,'Advanced Filters','Tools'],
[41,'Priority Support','Support'],
[42,'SLA / Response Time','Support'],
[43,'Automatic Ticket ID','Support'],
[44,'User Risk / Fraud Center','Security'],
[45,'Provider Management','Providers'],
[46,'Automatic Provider Failover','Providers'],
[47,'System Health Dashboard','System'],
[48,'Maintenance Mode','System'],
[49,'Feature Toggle','Feature Control'],
[50,'Backup & Recovery','System'],
[51,'Data Privacy & Retention','Security'],
[52,'Emergency Global Lock','Security'],
[53,'User Panel Feature Control','Feature Control'],
[54,'Country-wise Feature Control','Feature Control'],
[55,'User Group Feature Control','Feature Control'],
[56,'Calling Control','Feature Control'],
[57,'Wallet Feature Control','Feature Control'],
[58,'Payment Method Control','Feature Control'],
[59,'SMS Feature Control','Feature Control'],
[60,'Support Feature Control','Feature Control'],
[61,'Promotion & Referral Control','Feature Control'],
[62,'Emergency Feature Disable','Feature Control'],
[63,'Maintenance Control','Feature Control'],
[64,'Scheduled Feature Control','Feature Control'],
[65,'Feature OFF হলে User-কে Message','Feature Control'],
[66,'Feature Usage Analytics','Feature Control'],
[67,'Feature Control Audit','Feature Control'],
[68,'Dynamic User Feature / Module System','Feature Control'],
[69,'Talkify API / SDK / White-Label Integration','Developer'],
[70,'External Calling','Developer'],
[71,'External SMS','Developer'],
[72,'Developer API Keys','Developer'],
[73,'SDK','Developer'],
[74,'White-Label / Embedded User Panel','Developer'],
[75,'External App Admin Panel','Developer'],
[76,'External App Sub-Admin','Developer'],
[77,'External App Support','Developer'],
[78,'Master Admin Global Integration Dashboard','Developer'],
[79,'External App Security','Developer'],
[80,'External App Pricing','Developer'],
[81,'External App Wallet/Credit','Developer'],
[82,'Usage Limits','Developer'],
[83,'Webhooks','Developer'],
[84,'Request/Transaction IDs','Developer'],
[85,'Customer Number Protection / Number Masking','Developer'],
[86,'Multi-Tenant Architecture','Developer']
].map(([id,name,group])=>({id,name,group}));

app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}));

app.use(cors({
  origin:(process.env.ADMIN_ORIGIN||'').split(',').filter(Boolean),
  credentials:true
}));

app.use(express.json({limit:'1mb'}));

app.use(rateLimit({
  windowMs:15*60*1000,
  limit:300,
  standardHeaders:true,
  legacyHeaders:false
}));

const cookieSecure=String(process.env.COOKIE_SECURE||'true')==='true';

app.use(session({
  store:DATABASE_URL
    ?new PgSession({pool,tableName:'talkify_sessions',createTableIfMissing:true})
    :undefined,
  secret:process.env.SESSION_SECRET||'CHANGE_THIS_LONG_RANDOM_SECRET_BEFORE_DEPLOYMENT',
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:'lax',
    secure:cookieSecure,
    maxAge:8*60*60*1000
  }
}));

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins(
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'master_admin',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS feature_catalog(
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      group_name TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS admin_feature_permissions(
      admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
      feature_id INTEGER NOT NULL REFERENCES feature_catalog(id) ON DELETE CASCADE,
      can_view BOOLEAN NOT NULL DEFAULT FALSE,
      can_edit BOOLEAN NOT NULL DEFAULT FALSE,
      can_manage BOOLEAN NOT NULL DEFAULT FALSE,
      PRIMARY KEY(admin_id,feature_id)
    );

    CREATE TABLE IF NOT EXISTS app_settings(
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS audit_logs(
      id BIGSERIAL PRIMARY KEY,
      admin_id BIGINT,
      action TEXT NOT NULL,
      target TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS external_apps(
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT,
      app_id TEXT UNIQUE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_by BIGINT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  for(const f of FEATURES){
    await pool.query(
      'INSERT INTO feature_catalog(id,name,group_name) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,group_name=EXCLUDED.group_name',
      [f.id,f.name,f.group]
    );
  }
}

const asyncRoute=fn=>(req,res,next)=>
  Promise.resolve(fn(req,res,next)).catch(next);

function requireAdmin(req,res,next){
  if(!req.session?.adminId){
    return res.status(401).json({
      ok:false,
      message:'Admin login required'
    });
  }
  next();
}

function requireMaster(req,res,next){
  if(!req.session?.adminId||req.session.role!=='master_admin'){
    return res.status(403).json({
      ok:false,
      message:'Master Admin permission required'
    });
  }
  next();
}

// Server-side feature authorization.
// Master Admin bypasses Sub-Admin feature grants.
// Manage also allows Edit and View; Edit also allows View.
function requireFeature(featureId,action='view'){
  return asyncRoute(async(req,res,next)=>{
    if(!req.session?.adminId){
      return res.status(401).json({
        ok:false,
        message:'Admin login required'
      });
    }

    if(req.session.role==='master_admin') return next();

    const f=await pool.query(
      'SELECT enabled FROM feature_catalog WHERE id=$1',
      [featureId]
    );

    if(!f.rowCount||!f.rows[0].enabled){
      return res.status(403).json({
        ok:false,
        code:'FEATURE_DISABLED',
        message:'This feature is currently disabled by Master Admin.'
      });
    }

    const p=await pool.query(
      'SELECT can_view,can_edit,can_manage FROM admin_feature_permissions WHERE admin_id=$1 AND feature_id=$2',
      [req.session.adminId,featureId]
    );

    const grant=p.rows[0]||{};

    const allowed=action==='manage'
      ?grant.can_manage===true
      :action==='edit'
        ?(grant.can_edit===true||grant.can_manage===true)
        :(grant.can_view===true||grant.can_edit===true||grant.can_manage===true);

    if(!allowed){
      return res.status(403).json({
        ok:false,
        code:'FEATURE_PERMISSION_DENIED',
        feature_id:featureId,
        required_permission:action,
        message:'You do not have permission to use this feature.'
      });
    }

    next();
  });
}

async function audit(req,action,target='',details={}){
  await pool.query(
    'INSERT INTO audit_logs(admin_id,action,target,details,ip) VALUES($1,$2,$3,$4,$5)',
    [
      req.session?.adminId||null,
      action,
      target,
      JSON.stringify(details),
      req.ip
    ]
  );
}

app.get('/health',asyncRoute(async(req,res)=>{
  let db='ok';
  try{
    await pool.query('SELECT 1');
  }catch{
    db='error';
  }

  res.status(db==='ok'?200:503).json({
    ok:db==='ok',
    service:'Talkify Global Network',
    database:db,
    features:FEATURES.length
  });
}));

app.get('/api/admin/session',asyncRoute(async(req,res)=>{
  if(!req.session?.adminId){
    return res.json({authenticated:false});
  }

  const q=await pool.query(
    'SELECT id,email,role FROM admins WHERE id=$1 AND active=true',
    [req.session.adminId]
  );

  if(!q.rowCount){
    req.session.destroy(()=>{});
    return res.json({authenticated:false});
  }

  res.json({
    authenticated:true,
    admin:q.rows[0]
  });
}));

app.post('/api/admin/setup',asyncRoute(async(req,res)=>{
  const {email,password}=req.body||{};

  if(!email||!/^\S+@\S+\.\S+$/.test(email)||
     typeof password!=='string'||password.length<12){
    return res.status(400).json({
      message:'Valid email and password (12+ characters) required'
    });
  }

  const count=await pool.query('SELECT count(*)::int n FROM admins');

  if(count.rows[0].n>0){
    return res.status(403).json({
      message:'Initial setup is closed. Ask an existing Master Admin.'
    });
  }

  const hash=await bcrypt.hash(password,12);

  const q=await pool.query(
    "INSERT INTO admins(email,password_hash,role) VALUES($1,$2,'master_admin') RETURNING id,email,role",
    [email.toLowerCase(),hash]
  );

  req.session.regenerate(err=>{
    if(err){
      return res.status(500).json({
        message:'Session could not be created'
      });
    }

    req.session.adminId=q.rows[0].id;
    req.session.role=q.rows[0].role;

    req.session.save(e=>{
      if(e){
        return res.status(500).json({
          message:'Session could not be saved'
        });
      }

      res.status(201).json({
        ok:true,
        admin:q.rows[0]
      });
    });
  });
}));

app.post('/api/admin/login',asyncRoute(async(req,res)=>{
  const {email,password}=req.body||{};

  const q=await pool.query(
    'SELECT id,email,password_hash,role,active FROM admins WHERE lower(email)=lower($1)',
    [String(email||'')]
  );

  const a=q.rows[0];

  if(!a||!a.active||
     !await bcrypt.compare(String(password||''),a.password_hash)){
    return res.status(401).json({
      message:'Invalid credentials'
    });
  }

  req.session.regenerate(err=>{
    if(err){
      return res.status(500).json({
        message:'Session could not be created'
      });
    }

    req.session.adminId=a.id;
    req.session.role=a.role;

    req.session.save(async e=>{
      if(e){
        return res.status(500).json({
          message:'Session could not be saved'
        });
      }

      try{
        await audit(req,'admin_login','admin',{email:a.email});
      }catch{}

      res.json({
        ok:true,
        admin:{
          id:a.id,
          email:a.email,
          role:a.role
        }
      });
    });
  });
}));

app.post('/api/admin/forgot-password',(req,res)=>{
  res.json({
    ok:true,
    message:'If account recovery is configured, instructions will be sent. Configure an email provider before relying on this flow.'
  });
});

app.post('/api/admin/reset-password',(req,res)=>{
  res.status(501).json({
    message:'Password reset token/email delivery is not configured yet.'
  });
});

app.post('/api/admin/2fa/verify',(req,res)=>{
  res.status(501).json({
    message:'2FA provider/enrollment is not configured yet.'
  });
});

app.post('/api/admin/logout',(req,res)=>{
  req.session.destroy(()=>{
    res.clearCookie('connect.sid');
    res.json({ok:true});
  });
});

app.post('/api/admin/change-password',requireAdmin,asyncRoute(async(req,res)=>{
  const {currentPassword,newPassword}=req.body||{};

  if(typeof newPassword!=='string'||newPassword.length<12){
    return res.status(400).json({
      message:'New password must contain at least 12 characters'
    });
  }

  const q=await pool.query(
    'SELECT password_hash FROM admins WHERE id=$1',
    [req.session.adminId]
  );

  if(!q.rowCount||
     !await bcrypt.compare(String(currentPassword||''),q.rows[0].password_hash)){
    return res.status(400).json({
      message:'Current password is incorrect'
    });
  }

  await pool.query(
    'UPDATE admins SET password_hash=$1 WHERE id=$2',
    [await bcrypt.hash(newPassword,12),req.session.adminId]
  );

  await audit(req,'password_changed','admin');
  res.json({ok:true});
}));

app.get('/api/admin/features',requireAdmin,asyncRoute(async(req,res)=>{
  let q;

  if(req.session.role==='master_admin'){
    q=await pool.query(
      'SELECT id,name,group_name AS "group",enabled FROM feature_catalog ORDER BY id'
    );
  }else{
    q=await pool.query(
      'SELECT f.id,f.name,f.group_name AS "group",f.enabled FROM feature_catalog f JOIN admin_feature_permissions p ON p.feature_id=f.id AND p.admin_id=$1 WHERE f.enabled=true AND (p.can_view=true OR p.can_edit=true OR p.can_manage=true) ORDER BY f.id',
      [req.session.adminId]
    );
  }

  let permissions=[];

  if(req.session.role!=='master_admin'){
    const p=await pool.query(
      'SELECT feature_id,can_view,can_edit,can_manage FROM admin_feature_permissions WHERE admin_id=$1',
      [req.session.adminId]
    );
    permissions=p.rows;
  }

  res.json({
    features:q.rows,
    permissions
  });
}));

app.put('/api/admin/features/:id',requireMaster,asyncRoute(async(req,res)=>{
  const id=Number(req.params.id);

  if(!FEATURES.some(f=>f.id===id)){
    return res.status(404).json({
      message:'Unknown feature ID'
    });
  }

  const enabled=!!req.body?.enabled;

  await pool.query(
    'UPDATE feature_catalog SET enabled=$1,updated_at=now() WHERE id=$2',
    [enabled,id]
  );

  await audit(req,'feature_toggled',String(id),{enabled});

  res.json({ok:true,id,enabled});
}));

app.get('/api/admin/subadmins',requireMaster,asyncRoute(async(req,res)=>{
  const q=await pool.query(
    "SELECT id,email,role,active,created_at FROM admins WHERE role='sub_admin' ORDER BY id DESC"
  );

  res.json({subadmins:q.rows});
}));

app.post('/api/admin/subadmins',requireMaster,asyncRoute(async(req,res)=>{
  const {email,password}=req.body||{};

  if(!email||typeof password!=='string'||password.length<12){
    return res.status(400).json({
      message:'Email and a 12+ character temporary password are required'
    });
  }

  const c=await pool.connect();

  try{
    await c.query('BEGIN');

    const q=await c.query(
      "INSERT INTO admins(email,password_hash,role) VALUES($1,$2,'sub_admin') RETURNING id,email,role,active,created_at",
      [email.toLowerCase(),await bcrypt.hash(password,12)]
    );

    for(const f of FEATURES){
      await c.query(
        'INSERT INTO admin_feature_permissions(admin_id,feature_id,can_view,can_edit,can_manage) VALUES($1,$2,false,false,false)',
        [q.rows[0].id,f.id]
      );
    }

    await c.query('COMMIT');

    await audit(req,'subadmin_created',String(q.rows[0].id),{
      email:email.toLowerCase()
    });

    res.status(201).json({
      ok:true,
      subadmin:q.rows[0]
    });
  }catch(e){
    await c.query('ROLLBACK');
    throw e;
  }finally{
    c.release();
  }
}));

app.get('/api/admin/subadmins/:id/permissions',requireMaster,asyncRoute(async(req,res)=>{
  const exists=await pool.query(
    "SELECT id FROM admins WHERE id=$1 AND role='sub_admin'",
    [req.params.id]
  );

  if(!exists.rowCount){
    return res.status(404).json({
      ok:false,
      message:'Sub-Admin not found'
    });
  }

  const q=await pool.query(
    'SELECT f.id,f.name,f.group_name AS "group",p.can_view,p.can_edit,p.can_manage FROM feature_catalog f LEFT JOIN admin_feature_permissions p ON p.feature_id=f.id AND p.admin_id=$1 ORDER BY f.id',
    [req.params.id]
  );

  res.json({permissions:q.rows});
}));

app.put('/api/admin/subadmins/:id/permissions',requireMaster,asyncRoute(async(req,res)=>{
  const exists=await pool.query(
    "SELECT id FROM admins WHERE id=$1 AND role='sub_admin'",
    [req.params.id]
  );

  if(!exists.rowCount){
    return res.status(404).json({
      ok:false,
      message:'Sub-Admin not found'
    });
  }

  const items=req.body?.permissions;

  if(!Array.isArray(items)||items.length>86){
    return res.status(400).json({
      message:'permissions must be an array of up to 86 items'
    });
  }

  const c=await pool.connect();

  try{
    await c.query('BEGIN');

    for(const p of items){
      const id=Number(p.feature_id);

      if(!FEATURES.some(f=>f.id===id)){
        throw new Error('Invalid feature_id '+p.feature_id);
      }

      await c.query(
        'INSERT INTO admin_feature_permissions(admin_id,feature_id,can_view,can_edit,can_manage) VALUES($1,$2,$3,$4,$5) ON CONFLICT(admin_id,feature_id) DO UPDATE SET can_view=EXCLUDED.can_view,can_edit=EXCLUDED.can_edit,can_manage=EXCLUDED.can_manage',
        [
          req.params.id,
          id,
          !!(p.can_view||p.can_edit||p.can_manage),
          !!(p.can_edit||p.can_manage),
          !!p.can_manage
        ]
      );
    }

    await c.query('COMMIT');
  }catch(e){
    await c.query('ROLLBACK');
    throw e;
  }finally{
    c.release();
  }

  await audit(req,'subadmin_permissions_updated',String(req.params.id),{
    count:items.length
  });

  res.json({
    ok:true,
    updated:items.length
  });
}));

app.get('/api/admin/apps',requireMaster,asyncRoute(async(req,res)=>{
  const q=await pool.query(
    'SELECT id,name,company,app_id,status,created_at FROM external_apps ORDER BY id DESC'
  );

  res.json({apps:q.rows});
}));

app.post('/api/admin/apps',requireMaster,asyncRoute(async(req,res)=>{
  const {name,company,app_id}=req.body||{};

  if(!String(name||'').trim()){
    return res.status(400).json({
      message:'App name is required'
    });
  }

  const q=await pool.query(
    "INSERT INTO external_apps(name,company,app_id,created_by) VALUES($1,$2,$3,$4) RETURNING id,name,company,app_id,status,created_at",
    [
      String(name).trim(),
      company||null,
      app_id||'app_'+crypto.randomBytes(6).toString('hex'),
      req.session.adminId
    ]
  );

  await audit(req,'external_app_created',String(q.rows[0].id),{});

  res.status(201).json({
    ok:true,
    app:q.rows[0]
  });
}));

app.get('/api/admin/audit-logs',requireAdmin,requireFeature(26,'view'),asyncRoute(async(req,res)=>{
  const q=await pool.query(
    'SELECT id,admin_id,action,target,details,ip,created_at FROM audit_logs ORDER BY id DESC LIMIT 500'
  );

  res.json({logs:q.rows});
}));

app.get('/api/admin/dashboard/summary',requireAdmin,requireFeature(2,'view'),asyncRoute(async(req,res)=>{
  const u=await pool.query('SELECT count(*)::int total FROM admins');
  const f=await pool.query('SELECT count(*)::int total FROM feature_catalog WHERE enabled');

  res.json({
    summary:{
      total_users:'—',
      active_users:'—',
      total_wallet_balance:null,
      pending_kyc:'—',
      enabled_features:f.rows[0].total,
      admin_accounts:u.rows[0].total
    },
    system:{
      backend:'online',
      database:'connected'
    }
  });
}));

app.get('/api/admin/analytics/global',requireAdmin,requireFeature(24,'view'),(req,res)=>{
  res.json({
    calling:{status:'Not connected'},
    payments:{status:'Not connected'},
    sms:{status:'Not connected'},
    countries:{status:'Not connected'}
  });
});

app.get('/api/admin/countries',requireAdmin,requireFeature(11,'view'),(req,res)=>{
  res.json({countries:[]});
});

app.get('/api/admin/users',requireAdmin,requireFeature(3,'view'),(req,res)=>{
  res.json({
    users:[],
    notice:'User schema/provider integration is not configured in this foundation.'
  });
});

app.get('/api/admin/kyc',requireAdmin,requireFeature(4,'view'),(req,res)=>{
  res.json({
    kyc:[],
    notice:'KYC schema/storage integration is not configured.'
  });
});

app.get('/api/admin/calls',requireAdmin,requireFeature(9,'view'),(req,res)=>{
  res.json({calls:[]});
});

app.get('/api/admin/sms/history',requireAdmin,requireFeature(12,'view'),(req,res)=>{
  res.json({messages:[]});
});

app.get('/api/admin/wallet/transactions',requireAdmin,requireFeature(5,'view'),(req,res)=>{
  res.json({transactions:[]});
});

app.get('/api/admin/support/queue',requireAdmin,requireFeature(15,'view'),(req,res)=>{
  res.json({tickets:[]});
});

app.post('/api/admin/emergency-lock',requireMaster,asyncRoute(async(req,res)=>{
  await pool.query(
    "INSERT INTO app_settings(key,value) VALUES('emergency_global_lock','true'::jsonb) ON CONFLICT(key) DO UPDATE SET value='true'::jsonb,updated_at=now()"
  );

  await audit(req,'emergency_global_lock_enabled','system');

  res.json({ok:true,locked:true});
}));

app.get('/api/admin/settings/:key',requireAdmin,requireFeature(1,'view'),asyncRoute(async(req,res)=>{
  const q=await pool.query(
    'SELECT value FROM app_settings WHERE key=$1',
    [req.params.key]
  );

  res.json({
    key:req.params.key,
    value:q.rows[0]?.value??null
  });
}));

app.put('/api/admin/settings/:key',requireMaster,asyncRoute(async(req,res)=>{
  await pool.query(
    'INSERT INTO app_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()',
    [
      req.params.key,
      JSON.stringify(req.body?.value??null)
    ]
  );

  await audit(req,'setting_updated',req.params.key,{});

  res.json({ok:true});
}));

app.use((err,req,res,next)=>{
  console.error(err);

  res.status(500).json({
    ok:false,
    message:process.env.NODE_ENV==='production'
      ?'Internal server error'
      :err.message||'Internal server error'
  });
});

initDb()
  .then(()=>app.listen(PORT,()=>console.log(`Talkify server listening on ${PORT}`)))
  .catch(e=>{
    console.error('Database initialization failed:',e.message);
    process.exit(1);
  });
