"use strict";
// Deliberately no localStorage/sessionStorage: tokens stay in HttpOnly cookies;
// CSRF token lives in memory, lost on refresh; sign in again if necessary.
const byId = id => document.getElementById(id);
let csrf = "";
let grants = [];
function message(text){ byId("status").textContent = text; }
async function api(path, method="GET", body){
  const headers = {"Accept":"application/json"};
  if(method!=="GET"){headers["Content-Type"]="application/json";if(csrf)headers["X-CSRF-Token"]=csrf;}
  const response = await fetch(path,{method,headers,credentials:"same-origin",body:body?JSON.stringify(body):undefined});
  const data = await response.json();
  if(!response.ok) throw new Error(data.detail||data.error||"Request failed");
  return data;
}
function allowed(permission){return grants.includes(permission);}
function cell(text){const el=document.createElement("td");el.textContent=String(text??"");return el;}
function row(values){const tr=document.createElement("tr");values.forEach(v=>tr.appendChild(cell(v)));return tr;}
function stat(name,value){const el=document.createElement("div");el.className="stat";const b=document.createElement("b");b.textContent=String(value);const label=document.createElement("span");label.textContent=name;el.append(b,label);return el;}
async function load(){
  const me = await api("/api/auth/me");
  grants = me.permissions;
  byId("identity").textContent=`Signed in as ${me.username} · ${me.role}`;
  byId("login-panel").hidden=true;byId("workspace-panel").hidden=false;
  byId("reqs").hidden=!allowed("requisitions:read");
  byId("request-section").hidden=!allowed("requisitions:create");
  byId("approval-section").hidden=!allowed("requisitions:approve");
  byId("analytics-section").hidden=!allowed("metrics:read");
  byId("audit-section").hidden=!allowed("audit:read");
  if(allowed("requisitions:read")){
    const data=await api("/api/requisitions");byId("req-rows").replaceChildren(...data.items.map(r=>row([r.id,r.title,r.department,r.status])));
  }
  if(allowed("metrics:read")){
    const data=await api("/api/metrics");byId("stats").replaceChildren(stat("Requisitions",data.requisitions),stat("Applications",data.applications));
    byId("funnel").replaceChildren(...Object.entries(data.by_stage).map(([stage,count])=>{const p=document.createElement("p");p.textContent=`${stage}: ${count}`;return p;}));
  }
  if(allowed("audit:read")){
    const data=await api("/api/audit");byId("audit-rows").replaceChildren(...data.items.map(a=>row([a.event,a.actor,a.detail])));
  }
  message("Authenticated. Actions are limited by your assigned role.");
}
byId("login-form").addEventListener("submit",async e=>{
  e.preventDefault();
  try{
    const result=await api("/api/auth/login","POST",{username:byId("username").value,password:byId("password").value});
    csrf=result.csrf_token;byId("password").value="";await load();
  }catch(error){message(`Sign in failed: ${error.message}`);}
});
byId("logout").addEventListener("click",async()=>{
  try{await api("/api/auth/logout","POST",{});}catch(_error){};
  csrf="";grants=[];byId("login-panel").hidden=false;byId("workspace-panel").hidden=true;
  message("Signed out. Sign in to continue.");byId("username").focus();
});
byId("request-form").addEventListener("submit",async e=>{
  e.preventDefault();
  try{const result=await api("/api/requisitions","POST",{title:byId("job-title").value,department:byId("department").value,budget_usd:Number(byId("budget").value)});await load();message(`Submitted ${result.result.id} for review`);}
  catch(error){message(`Request failed: ${error.message}`);}
});
byId("approval-form").addEventListener("submit",async e=>{
  e.preventDefault();
  try{const result=await api("/api/requisitions/approve","POST",{req_id:byId("req-id").value});await load();message(`Approved ${result.result.id}`);}
  catch(error){message(`Approval failed: ${error.message}`);}
});
