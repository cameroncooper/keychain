const {test}=require("node:test");const assert=require("node:assert/strict");const fs=require("node:fs");const vm=require("node:vm");
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},fire(...args){for(const fn of this.listeners)fn(...args);}});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function fixture(target,{hold=false,manager=false}={}){
 const operations=[],nativePorts=[];let currentURL="https://example.com/login";
 const selected={id:"login",revision:7,content_binding:"a".repeat(64)};
 const runtime={id:"our-addon",onConnect:event(),sendMessage:async()=>{},connectNative(){
   const p={onMessage:event(),onDisconnect:event(),disconnected:false,
    disconnect(){if(this.disconnected)return;this.disconnected=true;this.onDisconnect.fire();},
    postMessage(message){operations.push(message);if(message.action==="fillLogin"&&hold)return;
     const result=message.action==="inspectLogins"?{kind:"logins",managerAvailable:manager,candidates:[{selection:selected,username:"alice",title:"Test",hasPassword:true,hasTotp:true}]}:message.action==="openManager"?{kind:"manager",available:true}:{kind:"login",id:"login",revision:7,password:"published synthetic password"};
     queueMicrotask(()=>{if(!p.disconnected)p.onMessage.fire({ok:true,result});});}};
   nativePorts.push(p);return p;
 }};
 const api={runtime,storage:{local:{get:async()=>({proxyEnabled:true})}},tabs:{get:async id=>({id,url:currentURL}),onRemoved:event()},webNavigation:{onBeforeNavigate:event()}};
 const context=vm.createContext({keychainApi:api,URL,crypto:require("node:crypto").webcrypto,setTimeout:(...args)=>setTimeout(...args).unref(),clearTimeout,console});
 vm.runInContext(fs.readFileSync(`${__dirname}/../shared/sender.js`,"utf8"),context);
 vm.runInContext(fs.readFileSync(`${__dirname}/../shared/forms-background.js`,"utf8"),context);
 function port(sender={}){
   const replies=[];const p={name:"keychain-login",sender:{id:"our-addon",tab:{id:4},frameId:0,url:"https://example.com/login",origin:"https://example.com",...sender},onMessage:event(),onDisconnect:event(),disconnected:false,
    disconnect(){if(this.disconnected)return;this.disconnected=true;this.onDisconnect.fire();},postMessage(message){replies.push(structuredClone(message));}};
   runtime.onConnect.fire(p);return {p,replies,send:message=>p.onMessage.fire(message)};
 }
 return {port,api,operations,nativePorts,selected,forms:context.keychainForms,navigate(url){currentURL=url;},target};
}
for(const target of ["chromium","firefox"]){
 test(`${target}: form inspection freezes browser origin and selected revision`,async()=>{
  const f=fixture(target),p=f.port();p.send({kind:"inspect",field:"password"});await tick();
  assert.equal(p.replies[0].kind,"candidates");assert.equal(JSON.stringify(p.replies).includes("content_binding"),false);
  p.send({kind:"fill",field:"password",id:"login"});await tick();await tick();
  assert.equal(f.operations[1].context.origin,"https://example.com");assert.deepEqual(f.operations[1].selection,f.selected);
  assert.equal(p.replies.at(-1).result.password,"published synthetic password");
 });
 test(`${target}: opaque origins, subframes and foreign extensions cannot inspect logins`,async()=>{
  for(const sender of [{origin:"null"},{frameId:1},{id:"another-addon"},{url:"http://example.com",origin:"http://example.com"}]){
   const f=fixture(target),p=f.port(sender);assert.equal(p.p.disconnected,true);assert.equal(f.operations.length,0);
  }
 });
 test(`${target}: unoffered selection and notes are refused before a private operation`,async()=>{
  for(const selection of [{id:"other",field:"password"},{id:"login",field:"notes"}]){
   const f=fixture(target),p=f.port();p.send({kind:"inspect",field:"password"});await tick();p.send({kind:"fill",...selection});await tick();
   assert.equal(f.operations.filter(item=>item.action==="fillLogin").length,0);
  }
 });
 test(`${target}: disconnect cancels a sleeping private request and drops a late result`,async()=>{
  const f=fixture(target,{hold:true}),p=f.port();p.send({kind:"inspect",field:"password"});await tick();p.send({kind:"fill",field:"password",id:"login"});await tick();
  const native=f.nativePorts.at(-1);p.p.disconnect();await tick();assert.equal(native.disconnected,true);
  native.onMessage.fire({ok:true,result:{kind:"login",id:"login",revision:7,password:"late synthetic password"}});await tick();
  assert.equal(p.replies.some(reply=>reply.kind==="fill"),false);
 });
 test(`${target}: navigation before private completion suppresses fields`,async()=>{
  const f=fixture(target,{hold:true}),p=f.port();p.send({kind:"inspect",field:"password"});await tick();p.send({kind:"fill",field:"password",id:"login"});await tick();
  f.navigate("https://other.example");f.nativePorts.at(-1).onMessage.fire({ok:true,result:{kind:"login",id:"login",revision:7,password:"synthetic"}});await tick();
  assert.equal(p.replies.some(reply=>reply.kind==="fill"),false);
 });
 test(`${target}: toolbar selection requires the original tab and opaque handle`,async()=>{
  const f=fixture(target),p=f.port();p.send({kind:"inspect",field:"password"});await tick();
  const offered=await f.forms.prepare(4);assert.equal(offered.loading,false);
  await assert.rejects(()=>f.forms.choose(9,offered.handle,"login"));
  await f.forms.choose(4,offered.handle,"login");assert.equal(p.replies.at(-1).kind,"select");
  await assert.rejects(()=>f.forms.choose(4,offered.handle,"login"));
 });
 test(`${target}: manager handoff is available only when the native host advertises it`,async()=>{
  for(const manager of [false,true]) {
   const f=fixture(target,{manager}),p=f.port();p.send({kind:"inspect",field:"username"});await tick();
   assert.equal(p.replies[0].managerAvailable,manager);
   p.send({kind:"manager",executable:"ignored",args:["ignored"]});await tick();
   assert.equal(f.operations.filter(item=>item.action==="openManager").length,manager?1:0);
   if(manager)assert.deepEqual(JSON.parse(JSON.stringify(f.operations[1])),{version:1,action:"openManager"});
  }
 });
 test(`${target}: username-first filling uses only public selected metadata`,async()=>{
  const f=fixture(target),p=f.port();p.send({kind:"inspect",field:"username"});await tick();p.send({kind:"fill",field:"username",id:"login"});await tick();
  assert.equal(p.replies.at(-1).username,"alice");assert.equal(f.operations.length,1);
 });
}
