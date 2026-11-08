const {test}=require("node:test"); const assert=require("node:assert/strict");const fs=require("node:fs");const vm=require("node:vm");
async function fixture(target){
  const created=[];
  class Element{
    constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.dataset={};this.disabled=false;created.push(this);}
    append(...items){this.children.push(...items);} addEventListener(name,fn){this.listeners[name]=fn;}
    setAttribute(){} focus(){document.activeElement=this;} click(){if(!this.disabled)return this.listeners.click?.();}
  }
  const nodes=new Map();const document={activeElement:null,querySelector(name){if(!nodes.has(name))nodes.set(name,new Element(name));return nodes.get(name);},createElement:name=>new Element(name),addEventListener(name,fn){this[name]=fn;}};
  const messages=[];let closed=false;
  const runtime={onMessage:{addListener(){}},async sendMessage(message){messages.push(message);if(message.type==="getPending")return {ok:true,pending:{kind:"get",inspection:{rpId:"example.com",origin:"https://example.com",biometric:true,candidates:[{id:"one",username:"alice"},{id:"two",username:"bob"}]}}};return {ok:true};}};
  const context=vm.createContext({document,URLSearchParams,location:{search:"?requestId=42"},window:{close(){closed=true;}},[target==="firefox"?"browser":"chrome"]:{runtime}});
  vm.runInContext(fs.readFileSync(`${__dirname}/../shared/approval.js`,"utf8"),context);await new Promise(resolve=>setImmediate(resolve));
  return {document,nodes,messages,created,closed:()=>closed,rows:created.filter(node=>node.className==="account")};
}
for(const target of ["chromium","firefox"]){
 test(`${target}: Escape cancels without choosing or starting another operation`,async()=>{const f=await fixture(target);f.document.keydown({key:"Escape",preventDefault(){}});await new Promise(resolve=>setImmediate(resolve));assert.equal(f.messages.at(-1).type,"deny");assert.equal(f.closed(),true);assert.equal(f.messages.some(m=>m.type==="approve"),false);});
 test(`${target}: selecting an account row immediately approves that exact account once`,async()=>{const f=await fixture(target);f.rows[1].click();f.rows[1].click();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.messages.at(-1).type,"approve");assert.equal(f.messages.at(-1).passkeyId,"two");assert.equal(f.messages.filter(m=>m.type==="approve").length,1);});
 test(`${target}: Arrow keys move keyboard focus between account rows`,async()=>{const f=await fixture(target);assert.equal(f.document.activeElement,f.rows[0]);f.rows[0].listeners.keydown({key:"ArrowDown",preventDefault(){}});assert.equal(f.document.activeElement,f.rows[1]);f.rows[1].listeners.keydown({key:"ArrowDown",preventDefault(){}});assert.equal(f.document.activeElement,f.rows[0]);});
}
