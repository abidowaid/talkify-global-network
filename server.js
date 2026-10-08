<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Talkify Admin - Secure Authentication</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-15px)}}.animate-float{animation:float 2.5s ease-in-out infinite}
#fireworks-canvas{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:1}
.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;display:inline-block;animation:spin .7s linear infinite;vertical-align:middle;margin-right:8px}@keyframes spin{to{transform:rotate(360deg)}}.hidden-important{display:none!important}
</style>
</head>
<body class="bg-slate-100 text-slate-800 min-h-screen flex flex-col items-center justify-center p-4 relative font-sans">

<div id="splash-screen" class="absolute inset-0 bg-gradient-to-tr from-slate-900 via-teal-900 to-cyan-900 z-50 flex flex-col items-center justify-between text-center p-10 transition-opacity duration-700">
<div></div>
<div class="animate-float space-y-4 z-10 relative flex flex-col items-center">
<div class="w-24 h-24 rounded-3xl p-1 bg-gradient-to-tr from-emerald-400 via-cyan-500 to-blue-500 shadow-2xl flex items-center justify-center">
<div class="w-full h-full rounded-2xl bg-slate-900/90 flex items-center justify-center border border-cyan-500/30">
<svg class="w-12 h-12 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a2 2 0 012 2v1a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z"/></svg>
</div></div>
<h1 class="text-3xl font-extrabold tracking-wider bg-gradient-to-r from-emerald-300 via-cyan-300 to-blue-400 bg-clip-text text-transparent">Talkify Admin Portal</h1>
</div>
<div class="z-10 pb-4"><p class="text-cyan-200/70 text-xs tracking-[0.25em] uppercase font-semibold">Developed by MD AJIJUL ISLAM</p></div>
<canvas id="fireworks-canvas"></canvas>
</div>

<div id="login-container" class="w-full max-w-md bg-white p-8 rounded-2xl shadow-xl border border-slate-200 z-10 hidden">
<h1 class="text-2xl font-bold text-center text-slate-800">Talkify Admin</h1>
<p class="text-center text-xs text-slate-500 mt-1 mb-6">Secure Master Administration</p>

<div id="login-view">
<div class="space-y-4">
<div><label class="block text-xs uppercase tracking-wider text-slate-500 mb-1">Admin Email</label><input id="login-email" type="email" autocomplete="username" placeholder="your@email.com" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600"></div>
<div><label class="block text-xs uppercase tracking-wider text-slate-500 mb-1">Talkify Admin Password</label><input id="login-password" type="password" autocomplete="current-password" placeholder="••••••••" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600"></div>
<button id="login-btn" onclick="loginMaster()" class="w-full bg-teal-600 hover:bg-teal-700 text-white py-3 rounded-xl font-bold shadow-md transition">Login as Master</button>
<div class="flex justify-between text-xs"><button onclick="openForgotPassword()" class="text-teal-600 hover:text-teal-800 font-semibold">Forgot Password?</button><button onclick="openFirstSetup()" class="text-slate-500 hover:text-teal-700">First-time Setup</button></div>
</div>
<div class="mt-6 bg-slate-50 border border-slate-200 rounded-xl p-4"><div class="flex gap-3"><div class="w-9 h-9 rounded-lg bg-teal-100 flex items-center justify-center flex-shrink-0">🔐</div><div><p class="text-xs font-bold text-slate-700">Secure Authentication</p><p class="text-[11px] text-slate-500 mt-1 leading-relaxed">Talkify Admin password is separate from your Gmail password. Credentials are handled by the secure backend.</p></div></div></div>
</div>

<div id="setup-view" class="hidden">
<div class="mb-5"><h2 class="font-bold text-lg text-slate-800">Create Master Admin</h2><p class="text-xs text-slate-500 mt-1">প্রথমবার Talkify Master Admin account তৈরি করুন।</p></div>
<div class="space-y-4">
<input id="setup-email" type="email" autocomplete="email" placeholder="Admin email" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<input id="setup-password" type="password" autocomplete="new-password" placeholder="Minimum 12 characters" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<input id="setup-confirm-password" type="password" autocomplete="new-password" placeholder="Repeat password" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<div class="bg-amber-50 border border-amber-200 rounded-xl p-3"><p class="text-xs font-semibold text-amber-800">Password Security</p><p class="text-[11px] text-amber-700 mt-1">কমপক্ষে 12 অক্ষরের শক্তিশালী password ব্যবহার করুন। Gmail password ব্যবহার করবেন না।</p></div>
<button id="setup-btn" onclick="createMasterAdmin()" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-xl font-bold shadow-md transition">Create Master Admin</button>
<button onclick="showLogin()" class="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 py-3 rounded-xl font-semibold">Back to Login</button>
</div></div>

<div id="forgot-view" class="hidden">
<div class="mb-5"><h2 class="font-bold text-lg text-slate-800">Forgot Password</h2><p class="text-xs text-slate-500 mt-1">আপনার Admin email দিন। Backend secure recovery process শুরু করবে।</p></div>
<div class="space-y-4"><input id="forgot-email" type="email" autocomplete="email" placeholder="Admin email" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<button id="forgot-btn" onclick="requestPasswordReset()" class="w-full bg-teal-600 hover:bg-teal-700 text-white py-3 rounded-xl font-bold">Send Recovery</button>
<button onclick="showLogin()" class="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 py-3 rounded-xl font-semibold">Back to Login</button></div></div>

<div id="status-message" class="text-xs text-center mt-5 min-h-[18px]"></div>
</div>

<div id="reset-container" class="hidden-important fixed inset-0 z-[100] bg-slate-900/65 backdrop-blur-sm flex items-center justify-center p-4">
<div class="bg-white w-full max-w-md rounded-2xl p-7 shadow-2xl"><h2 class="text-xl font-bold text-slate-800">Set New Password</h2><p class="text-xs text-slate-500 mt-1 mb-5">আপনার নতুন Talkify Admin password সেট করুন।</p>
<div class="space-y-4"><input id="reset-password" type="password" autocomplete="new-password" placeholder="New password" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<input id="reset-confirm" type="password" autocomplete="new-password" placeholder="Confirm new password" class="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:border-teal-600">
<button id="reset-btn" onclick="resetPassword()" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-xl font-bold">Change Password</button></div></div></div>

<script>
const API_BASE_URL="https://talkify-global-network.onrender.com";
const API={setup:API_BASE_URL+"/api/admin/auth/setup",login:API_BASE_URL+"/api/admin/auth/login",session:API_BASE_URL+"/api/admin/auth/session",forgotPassword:API_BASE_URL+"/api/admin/auth/forgot-password",resetPassword:API_BASE_URL+"/api/admin/auth/reset-password",verify2FA:API_BASE_URL+"/api/admin/auth/2fa/verify"};
const DASHBOARD_PAGE="dashboard.html";

const canvas=document.getElementById("fireworks-canvas"),ctx=canvas.getContext("2d");
function resizeCanvas(){canvas.width=innerWidth;canvas.height=innerHeight}addEventListener("resize",resizeCanvas);resizeCanvas();

class Particle{
constructor(x,y,c){
this.x=x;this.y=y;this.color=c;
let a=Math.random()*Math.PI*2,s=Math.random()*6+2;
this.vx=Math.cos(a)*s;this.vy=Math.sin(a)*s;
this.alpha=1;this.decay=Math.random()*.02+.015
}
update(){this.x+=this.vx;this.y+=this.vy;this.vy+=.05;this.alpha-=this.decay}
draw(){
ctx.save();
ctx.globalAlpha=this.alpha;
ctx.beginPath();
ctx.arc(this.x,this.y,3,0,Math.PI*2);
ctx.fillStyle=this.color;
ctx.fill();
ctx.restore()
}
}

let particles=[],animationId;

function createFirework(){
let x=Math.random()*(canvas.width-200)+100,
y=Math.random()*(canvas.height/2),
cs=["#34d399","#06b6d4","#38bdf8","#10b981"],
c=cs[Math.floor(Math.random()*cs.length)];
for(let i=0;i<40;i++)particles.push(new Particle(x,y,c))
}

function animateFireworks(){
ctx.fillStyle="rgba(4,47,46,.2)";
ctx.fillRect(0,0,canvas.width,canvas.height);
for(let i=particles.length-1;i>=0;i--){
particles[i].update();
particles[i].draw();
if(particles[i].alpha<=0)particles.splice(i,1)
}
animationId=requestAnimationFrame(animateFireworks)
}

animateFireworks();
const fireworkInterval=setInterval(createFirework,600);

addEventListener("DOMContentLoaded",()=>{
setTimeout(()=>{
clearInterval(fireworkInterval);
cancelAnimationFrame(animationId);
let s=document.getElementById("splash-screen");
s.style.opacity="0";
setTimeout(()=>{
s.style.display="none";
document.getElementById("login-container").classList.remove("hidden");
checkExistingSession()
},700)
},3000)
});

function hideAllViews(){
["login-view","setup-view","forgot-view"].forEach(id=>document.getElementById(id).classList.add("hidden"))
}

function showLogin(){
hideAllViews();
document.getElementById("login-view").classList.remove("hidden");
clearStatus()
}

function openFirstSetup(){
hideAllViews();
document.getElementById("setup-view").classList.remove("hidden");
clearStatus()
}

function openForgotPassword(){
hideAllViews();
document.getElementById("forgot-view").classList.remove("hidden");
clearStatus()
}

function showStatus(m,t="error"){
let e=document.getElementById("status-message");
e.innerText=m;
e.className=t==="success"
?"text-emerald-600 text-xs text-center mt-5 min-h-[18px]"
:t==="loading"
?"text-teal-600 text-xs text-center mt-5 min-h-[18px]"
:"text-rose-500 text-xs text-center mt-5 min-h-[18px]"
}

function clearStatus(){
document.getElementById("status-message").innerText=""
}

function setButtonLoading(id,on,text){
let b=document.getElementById(id);
if(!b)return;
b.disabled=on;
if(on){
b.classList.add("opacity-70","cursor-not-allowed");
b.innerHTML='<span class="spinner"></span>Processing...'
}else{
b.classList.remove("opacity-70","cursor-not-allowed");
b.innerText=text
}
}

async function apiRequest(url,method,body=null){
let o={
method,
credentials:"include",
headers:{"Accept":"application/json"},
cache:"no-store"
};
if(body!==null){
o.headers["Content-Type"]="application/json";
o.body=JSON.stringify(body)
}
let r=await fetch(url,o),d=null;
try{d=await r.json()}catch(e){}
return{response:r,data:d}
}

async function createMasterAdmin(){
let email=document.getElementById("setup-email").value.trim(),
p=document.getElementById("setup-password").value,
c=document.getElementById("setup-confirm-password").value;

if(!email||!email.includes("@"))
return showStatus("সঠিক Admin email দিন।");

if(p.length<12)
return showStatus("Password কমপক্ষে 12 অক্ষরের হতে হবে।");

if(p!==c)
return showStatus("দুটি password একই নয়।");

showStatus("Master Admin account তৈরি হচ্ছে...","loading");
setButtonLoading("setup-btn",true,"Create Master Admin");

try{
let r=await apiRequest(API.setup,"POST",{email,password:p});

if(!r.response.ok){
showStatus(r.data?.message||"Master Admin account তৈরি করা যায়নি।");
return
}

document.getElementById("login-email").value=email;
document.getElementById("setup-password").value="";
document.getElementById("setup-confirm-password").value="";

showStatus("Master Admin account সফলভাবে তৈরি হয়েছে। এখন Login করুন।","success");
setTimeout(showLogin,1000)

}catch(e){
console.error(e);
showStatus("Server-এর সাথে সংযোগ করা যাচ্ছে না。")
}finally{
setButtonLoading("setup-btn",false,"Create Master Admin")
}
}

async function loginMaster(){
let email=document.getElementById("login-email").value.trim(),
p=document.getElementById("login-password").value;

if(!email||!p)
return showStatus("Email এবং password দিন।");

showStatus("Authentication হচ্ছে...","loading");
setButtonLoading("login-btn",true,"Login as Master");

try{
let r=await apiRequest(API.login,"POST",{email,password:p});

if(!r.response.ok){
showStatus(r.data?.message||"Login ব্যর্থ হয়েছে।");
return
}

let d=r.data;

if(d?.requires2FA===true){
showStatus("2FA verification প্রয়োজন।","loading");
openTwoFactorScreen(d.challengeId);
return
}

if(!d||d.authenticated!==true||d.role!=="master_admin"){
showStatus("Master Admin authentication সম্পূর্ণ হয়নি।");
return
}

showStatus("Login সফল। Dashboard খোলা হচ্ছে...","success");
setTimeout(()=>location.href=DASHBOARD_PAGE,300)

}catch(e){
console.error(e);
showStatus("Server-এর সাথে সংযোগ করা যাচ্ছে না।")
}finally{
setButtonLoading("login-btn",false,"Login as Master")
}
}

async function requestPasswordReset(){
let email=document.getElementById("forgot-email").value.trim();

if(!email||!email.includes("@"))
return showStatus("সঠিক Admin email দিন।");

showStatus("Recovery request পাঠানো হচ্ছে...","loading");
setButtonLoading("forgot-btn",true,"Send Recovery");

try{
let r=await apiRequest(API.forgotPassword,"POST",{email});

if(!r.response.ok){
showStatus(r.data?.message||"Recovery request গ্রহণ করা যায়নি।");
return
}

showStatus("যদি এই email-এর জন্য একটি Admin account থাকে, secure recovery instructions পাঠানো হয়েছে।","success")

}catch(e){
console.error(e);
showStatus("Server-এর সাথে সংযোগ করা যাচ্ছে না।")
}finally{
setButtonLoading("forgot-btn",false,"Send Recovery")
}
}

async function resetPassword(){
let p=document.getElementById("reset-password").value,
c=document.getElementById("reset-confirm").value,
t=new URLSearchParams(location.search).get("reset_token");

if(p.length<12)
return alert("Password কমপক্ষে 12 অক্ষরের হতে হবে।");

if(p!==c)
return alert("দুটি password একই নয়।");

if(!t)
return alert("Secure reset token পাওয়া যায়নি।");

setButtonLoading("reset-btn",true,"Change Password");

try{
let r=await apiRequest(API.resetPassword,"POST",{token:t,password:p});

if(!r.response.ok){
alert(r.data?.message||"Password পরিবর্তন করা যায়নি।");
return
}

alert("Password সফলভাবে পরিবর্তন হয়েছে।");
location.href=location.pathname

}catch(e){
console.error(e);
alert("Server-এর সাথে সংযোগ করা যাচ্ছে না।")
}finally{
setButtonLoading("reset-btn",false,"Change Password")
}
}

function openTwoFactorScreen(challengeId){
let code=prompt("আপনার 2FA OTP / verification code দিন:");

if(!code){
showStatus("2FA verification বাতিল হয়েছে।");
return
}

verifyTwoFactor(challengeId,code)
}

async function verifyTwoFactor(challengeId,code){
showStatus("2FA যাচাই হচ্ছে...","loading");

try{
let r=await apiRequest(API.verify2FA,"POST",{challengeId,code});

if(!r.response.ok){
showStatus(r.data?.message||"2FA verification ব্যর্থ হয়েছে।");
return
}

if(r.data?.authenticated===true&&r.data?.role==="master_admin"){
showStatus("2FA সফল। Dashboard খোলা হচ্ছে...","success");
setTimeout(()=>location.href=DASHBOARD_PAGE,300)
}else{
showStatus("2FA verification সম্পূর্ণ হয়নি।")
}

}catch(e){
console.error(e);
showStatus("2FA server-এর সাথে যোগাযোগ করা যাচ্ছে না.")
}
}

async function checkExistingSession(){
try{
let r=await apiRequest(API.session,"GET");

if(!r.response.ok)return;

if(r.data?.authenticated===true&&r.data?.role==="master_admin")
location.href=DASHBOARD_PAGE

}catch(e){
console.warn("Session check unavailable:",e)
}
}

function checkRecoveryToken(){
if(new URLSearchParams(location.search).get("reset_token"))
document.getElementById("reset-container").classList.remove("hidden-important")
}

checkRecoveryToken();

document.addEventListener("keydown",e=>{
if(e.key!=="Enter")return;

if(!document.getElementById("login-view").classList.contains("hidden"))
loginMaster();

else if(!document.getElementById("setup-view").classList.contains("hidden"))
createMasterAdmin();

else if(!document.getElementById("forgot-view").classList.contains("hidden"))
requestPasswordReset()
});
</script>
</body>
</html>
