// Real Chrome/Firefox runner with isolated profiles, HTTPS RP, and synthetic
// native provider. No real broker, SEP, Apple account or password state is used.
// node browser/tests/browser-harness.mjs chromium|firefox|both
// GECKODRIVER=/path/geckodriver FIREFOX_BINARY=/path/librewolf override discovery.
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import https from "node:https";
import net from "node:net";
import crypto from "node:crypto";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {detectionPage} from "./fixtures/pages.mjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fieldFixtures=JSON.parse(await fs.readFile(path.join(root,"browser/tests/fixtures/fields.json"),"utf8"));
const selection = process.argv[2] ?? "both";
const theme = process.env.KEYCHAIN_HARNESS_THEME ?? "light";
if (!["light","dark"].includes(theme)) throw new Error("Choose light or dark theme");
const skipDeadline = process.env.KEYCHAIN_HARNESS_SKIP_DEADLINE === "1";
if (!["chromium", "firefox", "both"].includes(selection)) throw new Error("Choose chromium, firefox or both");
execFileSync(process.execPath, [path.join(root, "browser/build.mjs")]);
const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "keychain-browser-harness-"));
await fs.chmod(workspace, 0o700);
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() {
  const socket = net.createServer(); await new Promise(resolve => socket.listen(0, "127.0.0.1", resolve));
  const value = socket.address().port; await new Promise(resolve => socket.close(resolve)); return value;
}
const clientScript = `
window.runKeychainChecks = async () => {
  const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (!available) throw new Error('Synthetic Keychain availability was not exposed');
  const created = await navigator.credentials.create({publicKey:{rp:{id:'localhost',name:'Local fixture'},
    user:{id:new TextEncoder().encode('test-user'),name:'test-user',displayName:'Synthetic user'},challenge,
    pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required'},extensions:{credProps:true}}});
  if (!(created instanceof PublicKeyCredential) || !(created.response instanceof AuthenticatorAttestationResponse)) throw new Error('Wrong registration prototypes: ' + JSON.stringify({credential:created instanceof PublicKeyCredential,response:created.response instanceof AuthenticatorAttestationResponse,proto:Object.getPrototypeOf(created)===PublicKeyCredential.prototype,rproto:Object.getPrototypeOf(created.response)===AuthenticatorAttestationResponse.prototype,keys:Object.keys(created)}));
  if (created.response.getPublicKeyAlgorithm() !== -7 || !created.response.getAuthenticatorData().byteLength || !created.getClientExtensionResults().credProps.rk) throw new Error('Registration accessors failed');
  const createdJSON = created.toJSON();
  const getChallenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:getChallenge,userVerification:'required',allowCredentials:[{type:'public-key',id:created.rawId}]}});
  if (!(assertion instanceof PublicKeyCredential) || !(assertion.response instanceof AuthenticatorAssertionResponse)) throw new Error('Wrong assertion prototypes');
  const result = assertion.toJSON();
  const controller = new AbortController();
  const pending = navigator.credentials.get({signal:controller.signal,publicKey:{rpId:'localhost',challenge:new Uint8Array(32).fill(0xee),userVerification:'required'}});
  setTimeout(()=>controller.abort(), 700);
  let aborted = false; try { await pending; } catch (error) { aborted = error.name === 'AbortError'; }
  if (!aborted) throw new Error('Abort did not reject with AbortError');
  let rejected = false; try { await navigator.credentials.get({publicKey:{rpId:'foreign.invalid',challenge:getChallenge}}); } catch (error) { rejected = error.name === 'SecurityError'; }
  if (!rejected) throw new Error('Foreign relying party was not rejected');
  let expired = false;
  if (${skipDeadline}) expired = true;
  else try { await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:new Uint8Array(32).fill(0xee),timeout:1000,userVerification:'required'}}); } catch(error) { expired = error.name === 'NotAllowedError'; }
  if (!expired) throw new Error('Timeout did not reject with NotAllowedError');
  const after = await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:getChallenge,userVerification:'required'}});
  if (after.id !== created.id) throw new Error('Fresh request after cancellation/timeout failed');
  return {available,created:createdJSON,createdChallenge:encode(challenge),assertion:result,challenge:encode(getChallenge),aborted,rejected,expired};
};`;
await fs.writeFile(path.join(workspace, "page.js"), clientScript);
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(workspace,"tls.key"),
  "-out", path.join(workspace,"tls.crt"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], {stdio:"ignore"});
const formsHTML = query => query.includes("totpChallenge") ? `<!doctype html><meta charset="utf-8"><title>Public TOTP form shape</title>
<style>body{font:14px system-ui;margin:24px}label,input{display:block}input{width:280px;height:32px;margin:6px 0 18px}</style>
<form id="login" action="/login/?mode=totpChallenge" method="post" autocomplete="off">
<label for="email">E-Mail Address</label><input type="email" name="email" id="email" placeholder="E-Mail Address">
<label for="password">Password</label><input type="password" name="password" id="password" placeholder="Password">
<label for="totpmfa">Enter your MFA Code:</label><input type="text" name="totpmfa" id="totpmfa" placeholder="123456">
<input type="submit" value="Log In"></form>
<script>window.submissions=0;document.querySelector("form").addEventListener("submit",event=>{event.preventDefault();window.submissions++});</script>` : `<!doctype html><meta charset="utf-8"><title>Keychain form fixture</title>
<style>body{font:14px system-ui;margin:24px}label,input{display:block}input{width:280px;height:32px;margin:6px 0 18px}form{margin:0 0 24px}</style>
<form id="login" action="/submit" method="post"><label>Username<input id="username" name="username" autocomplete="username"></label>
${query.includes("usernameOnly") ? "" : '<label>Password<input id="password" type="password" name="password" autocomplete="current-password"></label>'}
<button type="submit">Sign in</button></form>
<form id="otp" action="/verify" method="post"><label>Verification code<input id="code" name="otp" autocomplete="one-time-code" maxlength="6"></label></form>
<script>window.submissions=0;window.inputEvents=[];for(const form of document.forms)form.addEventListener('submit',event=>{event.preventDefault();window.submissions++});document.addEventListener('input',event=>window.inputEvents.push(event.target.id));</script>`;
const server = https.createServer({key:await fs.readFile(path.join(workspace,"tls.key")),cert:await fs.readFile(path.join(workspace,"tls.crt"))}, (req,res)=>{
  res.setHeader("Content-Type", req.url === "/page.js" ? "application/javascript" : "text/html");
  if(req.url.startsWith("/detection?")) {
    const name=new URL(req.url,"https://localhost").searchParams.get("fixture");
    const fixture=fieldFixtures.find(fixture=>fixture.name === name);
    res.end(fixture ? detectionPage(fixture) : "Unknown fixture");return;
  }
  res.end(req.url.startsWith("/forms") ? formsHTML(req.url) : req.url === "/page.js" ? clientScript : '<!doctype html><title>Keychain isolated test</title><script src="/page.js"></script>');
});
await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
const origin = `https://localhost:${server.address().port}`;
try {
for (const target of selection === "both" ? ["chromium","firefox"] : [selection]) {
  const dir=path.join(workspace,target); await fs.mkdir(dir,{mode:0o700});
  const home=path.join(dir,"home"); await fs.mkdir(home);
  const keys=crypto.generateKeyPairSync("ec",{namedCurve:"prime256v1",publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});
  const state={origin,id:crypto.randomBytes(32).toString("base64url"),id2:crypto.randomBytes(32).toString("base64url"),public:keys.publicKey,private:keys.privateKey,log:path.join(dir,"native.log")};
  const stateFile=path.join(dir,"fixture.json"); await fs.writeFile(stateFile,JSON.stringify(state),{mode:0o600});
  const host=path.join(dir,"native-host"); await fs.writeFile(host,`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(path.join(root,"browser/tests/native-fixture.cjs"))} ${quote(stateFile)}\n`,{mode:0o700});
  const profile=path.join(dir,"profile"); await fs.mkdir(profile);
  const manifest={name:"cameroncooper.keychain",description:"ISOLATED SYNTHETIC TEST ONLY",path:host,type:"stdio"};
  const dirs=target==="chromium"?[path.join(profile,"NativeMessagingHosts")]:[path.join(home,".mozilla/native-messaging-hosts"),path.join(home,".librewolf/native-messaging-hosts")];
  if(target==="chromium")manifest.allowed_origins=["chrome-extension://lcadeibeloholafalbgoehpbhnplmojh/"];
  else manifest.allowed_extensions=["keychain@cameroncooper"];
  for(const destination of dirs){await fs.mkdir(destination,{recursive:true});await fs.writeFile(path.join(destination,"cameroncooper.keychain.json"),JSON.stringify(manifest),{mode:0o600});}
  const servicePort=await port();
  const driverPath=target==="chromium"?(process.env.CHROMEDRIVER??"chromedriver"):(process.env.GECKODRIVER??path.join(root,".sep-check-extension-harness-tools/geckodriver"));
  const log=await fs.open(path.join(dir,"driver.log"),"w");
  const driver=spawn(driverPath,[`--port=${servicePort}`,...(target === "firefox" ? ["--allow-system-access"] : [])],{env:{...process.env,HOME:home,XDG_CONFIG_HOME:path.join(home,".config"),XDG_CACHE_HOME:path.join(home,".cache")},stdio:["ignore",log.fd,log.fd]});
  let session;
  async function wd(method,route,body){
    const response=await fetch(`http://127.0.0.1:${servicePort}${route}`,{method,headers:{"content-type":"application/json"},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(160000)});
    const result=await response.json();if(result.value?.error)throw new Error(`${route}: ${result.value.error}: ${result.value.message}`);return result.value;
  }
  try {
    for(let attempt=0;;attempt++){try{await wd("GET","/status");break;}catch(error){if(attempt===50)throw error;await sleep(100);}}
    const capabilities={acceptInsecureCerts:true};
    if(target==="chromium")capabilities["goog:chromeOptions"]={enableExtensionTargets:true,binary:process.env.CHROMIUM_BINARY??"/usr/local/bin/chromium",args:["--headless=new","--no-first-run","--no-default-browser-check",...(theme === "dark" ? ["--force-dark-mode"] : []),`--user-data-dir=${profile}`,`--load-extension=${path.join(root,"browser/dist/chromium")}`]};
    else capabilities["moz:firefoxOptions"]={binary:process.env.FIREFOX_BINARY??path.join(os.homedir(),".local/opt/librewolf/librewolf"),args:["-headless","-profile",profile],prefs:{"extensions.autoDisableScopes":0,"extensions.enabledScopes":15,"layout.css.prefers-color-scheme.content-override":theme === "dark" ? 0 : 1}};
    const started=await wd("POST","/session",{capabilities:{alwaysMatch:capabilities}});session=started.sessionId;
    if(target==="firefox"){
      const xpi=path.join(dir,"keychain.xpi");
      execFileSync("python3",["-c","import pathlib,sys,zipfile; root=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],'w'); [z.write(p,p.relative_to(root)) for p in root.rglob('*') if p.is_file()]; z.close()",path.join(root,"browser/dist/firefox"),xpi]);
      await wd("POST",`/session/${session}/moz/addon/install`,{path:xpi,temporary:true});
    }
    await wd("POST",`/session/${session}/timeouts`,{script:145000});
    await sleep(700);
    await wd("POST",`/session/${session}/url`,{url:origin});
    const result=await wd("POST",`/session/${session}/execute/async`,{script:"const done=arguments[arguments.length-1]; runKeychainChecks().then(result=>done({result}),error=>done({error:String(error),stack:error.stack}));",args:[]});
    if(result.error)throw new Error(`${target}: ${result.error}\n${result.stack}`);
    const value=result.result; assert.equal(value.created.id,state.id);assert.equal(value.assertion.id,state.id);
    const createdClient=JSON.parse(Buffer.from(value.created.response.clientDataJSON,"base64url"));
    assert.equal(createdClient.type,"webauthn.create"); assert.equal(createdClient.origin,origin); assert.equal(createdClient.challenge,value.createdChallenge);
    const createdAuth=Buffer.from(value.created.response.authenticatorData,"base64url");
    assert.equal(createdAuth.subarray(0,32).equals(crypto.createHash("sha256").update("localhost").digest()),true);
    assert.equal(createdAuth[32] & 5,5);
    const response=value.assertion.response;
    const client=Buffer.from(response.clientDataJSON,"base64url");const decoded=JSON.parse(client);
    assert.equal(decoded.origin,origin);assert.equal(decoded.challenge,value.challenge);assert.equal(decoded.type,"webauthn.get");
    const signed=Buffer.concat([Buffer.from(response.authenticatorData,"base64url"),crypto.createHash("sha256").update(client).digest()]);
    assert.equal(crypto.verify("sha256",signed,state.public,Buffer.from(response.signature,"base64url")),true);
    // Exercise the actual shared account picker, not a DOM/mock reimplementation.
    const mainHandle=await wd("GET",`/session/${session}/window`);
    await wd("POST",`/session/${session}/execute/sync`,{script:"window.multiResult={pending:true}; navigator.credentials.get({publicKey:{rpId:'localhost',challenge:new Uint8Array(32).fill(0xdd),userVerification:'required'}}).then(value=>{window.multiResult={id:value.id}},error=>{window.multiResult={error:String(error)}}); return true;",args:[]});
    let picker;
    for(let attempt=0;attempt<50;attempt++){
      const handles=await wd("GET",`/session/${session}/window/handles`); picker=handles.find(handle=>handle!==mainHandle);
      if(picker)break; await sleep(100);
    }
    assert.ok(picker,"The shared account picker did not open");
    await wd("POST",`/session/${session}/window`,{handle:picker});
    let choice;
    for(let attempt=0;attempt<50;attempt++){
      const elements=await wd("POST",`/session/${session}/elements`,{using:"css selector",value:'button[data-credential="fixture-2"]'});
      choice=elements[0]?.["element-6066-11e4-a52e-4f735466cecf"];
      if(choice)break;await sleep(100);
    }
    assert.ok(choice,"Account choices were not rendered");
    const pickerURL=await wd("GET",`/session/${session}/url`);
    await fs.writeFile(path.join(dir,`picker-${theme}.png`),Buffer.from(await wd("GET",`/session/${session}/screenshot`),"base64"));
    await wd("POST",`/session/${session}/element/${choice}/click`,{});
    await wd("POST",`/session/${session}/window`,{handle:mainHandle});
    let multi;
    for(let attempt=0;attempt<50;attempt++){
      multi=await wd("POST",`/session/${session}/execute/sync`,{script:"return window.multiResult",args:[]});
      if(!multi.pending)break;await sleep(100);
    }
    assert.equal(multi.id,state.id2,JSON.stringify(multi));
    const script=code=>wd("POST",`/session/${session}/execute/sync`,{script:code,args:[]});
    async function until(code, message) {
      for(let attempt=0;attempt<60;attempt++){const value=await script(code);if(value)return value;await sleep(75);}
      const diagnostic=await script("return {active:document.activeElement?.id,menu:document.querySelector('[data-keychain-menu]')?.dataset.keychainState,inputs:[...document.querySelectorAll('input')].map(field=>({id:field.id,type:field.type,autocomplete:field.autocomplete,maxLength:field.maxLength,visible:getComputedStyle(field).visibility,rect:field.getBoundingClientRect().toJSON()}))}").catch(()=>null);
      throw new Error(`${target}: ${message}: ${JSON.stringify(diagnostic)}`);
    }
    let capturedInline = false;
    async function chooseLogin(selector, row = 0) {
      const element=await wd("POST",`/session/${session}/element`,{using:"css selector",value:selector});
      await wd("POST",`/session/${session}/element/${element["element-6066-11e4-a52e-4f735466cecf"]}/click`,{});
      await until("return document.querySelector('[data-keychain-menu]')?.dataset.keychainState==='ready'","inline account menu was not ready");
      if(!capturedInline) { capturedInline=true;await fs.writeFile(path.join(dir,`inline-${theme}.png`),Buffer.from(await wd("GET",`/session/${session}/screenshot`),"base64")); }
      await wd("POST",`/session/${session}/actions`,{actions:[{type:"key",id:"keyboard",actions:[...Array.from({length:row+1},()=>[{type:"keyDown",value:"\ue015"},{type:"keyUp",value:"\ue015"}]).flat(),{type:"keyDown",value:"\ue007"},{type:"keyUp",value:"\ue007"}]}]});
    }
    await wd("POST",`/session/${session}/url`,{url:origin+"/forms"});
    await chooseLogin("#username");
    await until("return document.querySelector('#password').value==='published-browser-password'","password was not filled");
    assert.equal(await script("return document.querySelector('#username').value"),"test-user");
    assert.equal(await script("return window.submissions"),0);
    assert.equal(await script("return window.inputEvents.includes('username') && window.inputEvents.includes('password')"),true);
    await chooseLogin("#code");
    await until("return document.querySelector('#code').value==='123456'","verification code was not filled");
    // A changed destination or replacement field during authorization must not
    // receive the delayed synthetic private result.
    for(const mutate of ["document.querySelector('#login').action='https://foreign.invalid/submit'", "document.querySelector('#password').replaceWith(document.querySelector('#password').cloneNode())",
      "document.querySelector('#password').style.visibility='hidden'",
      "document.querySelector('#password').setAttribute('form','otp')",
      "document.querySelector('#username').setAttribute('aria-label','Newsletter email')",
      "document.querySelector('#login button').textContent='Create an account'",
      "document.querySelector('#login').append(document.createElement('input'))"]) {
      await wd("POST",`/session/${session}/url`,{url:origin+"/forms"});
      const before=(await fs.readFile(state.log,"utf8")).split("fillLogin").length;
      await chooseLogin("#username");
      for(let attempt=0;attempt<50;attempt++) { if((await fs.readFile(state.log,"utf8")).split("fillLogin").length>before)break;await sleep(10); }
      await script(mutate);await sleep(600);
      assert.equal(await script("return document.querySelector('#password').value"),"");
    }
    // Target routing attributes compare in full, even beyond classifier text bounds.
    await wd("POST",`/session/${session}/url`,{url:origin+"/forms"});
    await script("document.querySelector('#username').name='a'.repeat(600)");
    const beforeLongName=(await fs.readFile(state.log,"utf8")).split("fillLogin").length;
    await chooseLogin("#username");
    for(let attempt=0;attempt<50;attempt++) {if((await fs.readFile(state.log,"utf8")).split("fillLogin").length>beforeLongName)break;await sleep(10);}
    await script("document.querySelector('#username').name='a'.repeat(599)+'b'");await sleep(600);
    assert.equal(await script("return document.querySelector('#password').value"),"");
    await wd("POST",`/session/${session}/url`,{url:origin+"/forms?usernameOnly"});
    const privateBefore=(await fs.readFile(state.log,"utf8")).split("fillLogin").length;
    await chooseLogin("#username");
    await until("return document.querySelector('#username').value==='test-user'","username-first form was not filled");
    assert.equal((await fs.readFile(state.log,"utf8")).split("fillLogin").length,privateBefore);
    // Passkey metadata can fill a username, even on a form that also has a
    // password input. It must not request a password or submit/sign anything.
    for (const page of ["/forms?usernameOnly", "/forms"]) {
      await wd("POST",`/session/${session}/url`,{url:origin+page});
      const before=(await fs.readFile(state.log,"utf8")).split("fillLogin").length;
      const assertionsBefore=(await fs.readFile(state.log,"utf8")).split("assert").length;
      await chooseLogin("#username",1);
      await until("return document.querySelector('#username').value==='passkey-user'","passkey username was not filled");
      assert.equal(await script("return document.querySelector('#password')?.value ?? ''"),"");
      assert.equal(await script("return window.submissions"),0);
      assert.equal((await fs.readFile(state.log,"utf8")).split("fillLogin").length,before);
      assert.equal((await fs.readFile(state.log,"utf8")).split("assert").length,assertionsBefore);
    }
    // Public authenticationtest.com form structure: autocomplete off, all
    // three fields in one form, and an unlabeled-by-autocomplete totpmfa input.
    for(const field of ["#email","#password"]) {
      await wd("POST",`/session/${session}/url`,{url:origin+"/forms?totpChallenge"});
      await chooseLogin(field);
      await until("return document.querySelector('#email').value==='test-user' && document.querySelector('#password').value==='published-browser-password'","public TOTP form login was not filled");
      await chooseLogin("#totpmfa");
      await until("return document.querySelector('#totpmfa').value==='123456'","totpmfa field was not filled");
      assert.equal(await script("return window.submissions"),0);
    }
    async function manualSelection(role, stale = false, refused = false) {
      let helper;
      const toolbarURL=new URL("toolbar.html",pickerURL).href;
      if(target === "firefox") {
        // LibreWolf disables WebDriver openWindow; its extension window API is
        // available (and is also how the production account picker opens).
        const bootstrap=await wd("POST",`/session/${session}/window/new`,{type:"tab"});
        await wd("POST",`/session/${session}/window`,{handle:bootstrap.handle});
        await wd("POST",`/session/${session}/url`,{url:toolbarURL});
        await wd("POST",`/session/${session}/execute/async`,{script:"const done=arguments[arguments.length-1];browser.windows.create({url:arguments[0],type:'popup'}).then(()=>done(true),error=>done({error:String(error)}));",args:[toolbarURL]});
        await wd("DELETE",`/session/${session}/window`);
        const handles=await wd("GET",`/session/${session}/window/handles`);
        helper={handle:handles.find(handle=>handle !== mainHandle)};
      } else {
        helper=await wd("POST",`/session/${session}/window/new`,{type:"window"});
      }
      await wd("POST",`/session/${session}/window`,{handle:helper.handle});
      await wd("POST",`/session/${session}/url`,{url:toolbarURL});
      const pageURL=await wd("POST",`/session/${session}/execute/async`,{script:`
        const done=arguments[arguments.length-1];const api=globalThis.browser??globalThis.chrome;
        (async()=>{const tabs=await api.tabs.query({});const tab=tabs.find(tab=>tab.url?.includes('/detection?'));
        const probe=await api.tabs.sendMessage(tab.id,{type:'keychainInspectForm'});window.manualProbe={tab:tab.id,...probe};return tab.url;})().then(done,error=>done({error:String(error)}));`,args:[]});
      assert.equal(typeof pageURL,"string",JSON.stringify(pageURL));
      if(stale) {await wd("POST",`/session/${session}/window`,{handle:mainHandle});await script("document.activeElement.setAttribute('name','changed-field')");await wd("POST",`/session/${session}/window`,{handle:helper.handle});}
      const response=await wd("POST",`/session/${session}/execute/async`,{script:`
        const role=arguments[0],done=arguments[arguments.length-1];const api=globalThis.browser??globalThis.chrome;
        api.tabs.sendMessage(window.manualProbe.tab,{type:'keychainInspectForm',manualRole:role,manualToken:window.manualProbe.manualToken}).then(done,error=>done({error:String(error)}));`,args:[role]});
      await wd("DELETE",`/session/${session}/window`);
      await wd("POST",`/session/${session}/window`,{handle:mainHandle});
      assert.equal(response.ok,!(stale || refused),JSON.stringify(response));
    }
    for(const fixture of fieldFixtures.filter(fixture=>fixture.browser !== false)) {
      await wd("POST",`/session/${session}/url`,{url:origin+"/detection?fixture="+fixture.name});
      await until("return document.querySelectorAll('input').length>0","dynamic fixture fields were not inserted");
      const id=fixture.fields[fixture.focus].id;
      const expected=fixture.expected[fixture.focus];
      const count=(await fs.readFile(state.log,"utf8")).split("inspectLogins").length;
      if(["excluded","new-password","unknown"].includes(expected)) {
        const element=await wd("POST",`/session/${session}/element`,{using:"css selector",value:"#"+id});
        await wd("POST",`/session/${session}/element/${element["element-6066-11e4-a52e-4f735466cecf"]}/click`,{});
        await sleep(120);
        assert.equal(await script("return !!document.querySelector('[data-keychain-menu]')"),false,fixture.name);
        assert.equal((await fs.readFile(state.log,"utf8")).split("inspectLogins").length,count,fixture.name);
        if(!fixture.manual) {
          if(["signup","credit-card-code","segmented-code","newsletter","unmasked-password-hint"].includes(fixture.name)) await manualSelection("totp",false,true);
          continue;
        }
        await manualSelection(fixture.manual);
      }
      await chooseLogin("#"+id);
      const fill=fixture.manual ?? fixture.fill;
      const target=fill === "password" ? fixture.fields.find(field=>field.type === "password" && !field.autocomplete?.includes("new-password"))?.id : id;
      const expectedValue=fill === "password" ? "published-browser-password" : fill === "totp" ? "123456" : "test-user";
      await until("return document.getElementById("+JSON.stringify(target)+").value==="+JSON.stringify(expectedValue),"fixture did not fill: "+fixture.name);
      assert.equal(await script("return window.submissions"),0,fixture.name);
      if(fill === "username") {
        assert.equal(await script("return [...document.querySelectorAll('input[type=password]')].every(field=>field.value==='')"),true,fixture.name+": username selection must not fill passwords");
      }
      if(fixture.usernameTarget !== undefined) {
        assert.equal(await script("return document.getElementById("+JSON.stringify(fixture.fields[fixture.usernameTarget].id)+").value"),"test-user");
        assert.equal(await script("return document.getElementById("+JSON.stringify(fixture.fields[0].id)+").value"),"");
      }
    }
    await wd("POST",`/session/${session}/url`,{url:origin+"/detection?fixture=unknown-code"});
    const uncertain=await wd("POST",`/session/${session}/element`,{using:"css selector",value:"#f1"});
    await wd("POST",`/session/${session}/element/${uncertain["element-6066-11e4-a52e-4f735466cecf"]}/click`,{});
    await manualSelection("totp",true);
    assert.equal(await script("return document.querySelector('#f1').value"),"");
    await wd("POST",`/session/${session}/url`,{url:new URL("toolbar.html",pickerURL).href});
    await sleep(500);
    await fs.writeFile(path.join(dir,`toolbar-${theme}.png`),Buffer.from(await wd("GET",`/session/${session}/screenshot`),"base64"));
    const html=await wd("POST",`/session/${session}/element`,{using:"css selector",value:"html"});
    const color=await wd("GET",`/session/${session}/element/${html["element-6066-11e4-a52e-4f735466cecf"]}/css/color`);
    assert.equal(color.replaceAll(" ","").includes(theme === "dark" ? "240,240,243" : "36,36,38"),true,`Wrong ${theme} theme: ${color}`);
    const operations=await fs.readFile(state.log,"utf8"); assert.match(operations,/create/);assert.match(operations,/assert/);
    await fs.writeFile(path.join(dir,"result.json"),JSON.stringify({passed:true,browser:started.capabilities.browserVersion,theme,checks:["availability","registration","credential prototypes/accessors","shared account picker","password/code filling","toolbar state/theme","changed form/field rejection","username-first metadata filling","passkey username suggestions without signing","public TOTP challenge form fields","shared detection corpus and negative fields","explicit manual roles and stale-probe refusal","assertion signature/origin/challenge","abort",...(skipDeadline ? [] : ["timeout"]),"fresh request after cancellation","foreign RP rejection"]},null,2));
    console.log(`${target}: passed registration, assertion verification, origin/RP, accessors, picker, password/code forms, abort${skipDeadline ? " (deadline skipped)" : " and timeout"} (${started.capabilities.browserVersion})`);
  } finally {if(session)await wd("DELETE",`/session/${session}`).catch(()=>{});driver.kill();await log.close();}
}
} finally {await new Promise(resolve=>server.close(resolve));console.log(`Isolated test evidence: ${workspace}`);}
