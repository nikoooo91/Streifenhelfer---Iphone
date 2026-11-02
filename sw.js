/* Generated: only public shell and authenticated ciphertext are cacheable. */
'use strict';
const FILES=[{"bytes":3059,"path":"index.html","sha256":"04a3274981876eec698213fb5be7ec3a6f18815281c020284a9b9d1cb9aa417e"},{"bytes":2319,"path":"shell.css","sha256":"fe93ddfca21d8a5762e6dde9ec1179a855204304c27109f1447e4617de532e3b"},{"bytes":9454,"path":"shell.mjs","sha256":"9da448c19d774459b6c39a1a4fd800e1d6c4de0c215ba2a4756efa3202ae9980"},{"bytes":9301,"path":"crypto.mjs","sha256":"04c9a48b09028b35aa02c015a54fa108e70e422d93e1d82c96e5f44225dffa8e"},{"bytes":275,"path":"manifest.webmanifest","sha256":"f50fc8e466ed3b01baaa6facffb293d49c6a17bfdc2d67478af4893a7a89e444"},{"bytes":31559,"path":"app-icon.png","sha256":"c9369397185f3c106dfc1d6fa8cb28b80f3c77189835476cbf9fc42ab578da3c"},{"bytes":2587,"path":"payload.json","sha256":"96cf54764e64987d4615b253c8b5be1f230a23a0dfe9fa75835a378fcebe18f5"},{"bytes":1048576,"path":"payload-105db095dea2d804-0001.bin","sha256":"6c30e54dbac0fa887dbeefa5146684d20b46668768416378a868c62ece54dced"},{"bytes":1048576,"path":"payload-105db095dea2d804-0002.bin","sha256":"fa1c49520ca343938a58f3f1186f7a55559249e6f00e409801725a4e433e3447"},{"bytes":1048576,"path":"payload-105db095dea2d804-0003.bin","sha256":"d0980ba291001c4a4567c1fa8e89ddddb8c7c33fc77a722345f0ed009af7bd5f"},{"bytes":1048576,"path":"payload-105db095dea2d804-0004.bin","sha256":"e237b6a72abd6a1e029e7d2926cb79e78e808aaff670cade02231301c4faa862"},{"bytes":1048576,"path":"payload-105db095dea2d804-0005.bin","sha256":"6e8ffa1f12f2023befc7f661fa6e95db5e901d8f48c3fe256308db9c0733fc18"},{"bytes":1048576,"path":"payload-105db095dea2d804-0006.bin","sha256":"67cc5906c6ad0f509a46b40faeb539e91afc595c04618dd0bfcee520f0b33351"},{"bytes":1048576,"path":"payload-105db095dea2d804-0007.bin","sha256":"b5debac3207ce515f025f946585ec7b0249aaebcf9febd0c4475bb4cb43f1aa4"},{"bytes":1048576,"path":"payload-105db095dea2d804-0008.bin","sha256":"7289e00da1beb5c6e8bb718e0fa3b246483ccf9114e8bfeb2795793ff3f0ad1d"},{"bytes":1048576,"path":"payload-105db095dea2d804-0009.bin","sha256":"32ffd49388a06d2cfe5efb85a6ad64bc194167cf78498cd891fb3d5d24c17dca"},{"bytes":1048576,"path":"payload-105db095dea2d804-0010.bin","sha256":"c614dd3d5388611e57e50f3cadfa3b58fa007d939f9b09dc603956a1e1551bed"},{"bytes":1048576,"path":"payload-105db095dea2d804-0011.bin","sha256":"7aa8c9251c82b436456e7c71b46be918ed738c8b7623ab6507586792548a1af4"},{"bytes":808192,"path":"payload-105db095dea2d804-0012.bin","sha256":"b74f1c167ea0fbc7596348a4a996af0856c220f74749ba3b9bf8fe572e61120c"}],VERSION="6afda113bfceefb89e7ebe0d";
const SCOPE=self.registration.scope;
const PREFIX='streifenhelfer-encrypted-'+encodeURIComponent(SCOPE)+'-';
const CONTROL=PREFIX+'control',SNAPSHOT=PREFIX+'snapshot-'+VERSION;
const STATE=new URL('__offline-control',SCOPE).href,MARKER=new URL('__offline-complete',SCOPE).href;
const TOKEN=new URL(self.location.href).searchParams.get('consent');
const ALLOWED=new Map(FILES.map(f=>[new URL(f.path,SCOPE).href,f]));
let canceled=false,download=null,installWork=null;
const digest=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('');
async function state(){const r=await(await caches.open(CONTROL)).match(STATE);return r?await r.json():null;}
async function authorized(){const s=await state();return !canceled&&typeof TOKEN==='string'&&/^[a-f0-9]{32}$/.test(TOKEN)&&s?.consent===TOKEN&&s.removed===false;}
async function ensure(){if(download?.signal.aborted||!await authorized())throw Error('Offline-Speicherung wurde abgebrochen.');}
async function valid(response,file){
 if(!response||!response.ok||response.type==='opaque'||response.type==='opaqueredirect'||response.redirected)return false;
 const copy=response.clone(),reader=copy.body?.getReader();if(!reader)return false;
 const parts=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>file.bytes){reader.cancel().catch(()=>{});response.body?.cancel().catch(()=>{});return false;}parts.push(value);}}
 catch{reader.cancel().catch(()=>{});response.body?.cancel().catch(()=>{});return false;}
 if(size!==file.bytes)return false;const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.byteLength;}
 return await digest(bytes)===file.sha256;
}
async function complete(full=false){
 const s=await state();if(s?.removed!==false||!s.consent)return false;
 const c=await caches.open(SNAPSHOT),mark=await c.match(MARKER);if(!mark)return false;
 const m=await mark.json();if(m.version!==VERSION||m.count!==FILES.length)return false;
 const keys=await c.keys();if(keys.length!==FILES.length+1)return false;
 if(full)for(const f of FILES)if(!await valid(await c.match(new URL(f.path,SCOPE).href),f))return false;
 const again=await state();return !canceled&&again?.removed===false&&again.consent===s.consent;
}
async function install(){
 const abort=new AbortController();download=abort;const timer=setTimeout(()=>abort.abort(),150000);
 try{
  await ensure();
  if(await complete(true)){await ensure();await self.skipWaiting();return;}
  await ensure();await caches.delete(SNAPSHOT);await ensure();const cache=await caches.open(SNAPSHOT);
  for(const f of FILES){
   await ensure();const url=new URL(f.path,SCOPE).href;
   const response=await fetch(url,{cache:'no-store',credentials:'omit',redirect:'error',signal:abort.signal});
   if(!await valid(response,f))throw Error('Offline-Datei fehlt, ist unvollständig oder wurde verändert.');
   await ensure();await cache.put(url,response);await ensure();
  }
  await ensure();await cache.put(MARKER,new Response(JSON.stringify({version:VERSION,count:FILES.length}),{headers:{'content-type':'application/json'}}));
  await ensure();await self.skipWaiting();
 }catch(e){await caches.delete(SNAPSHOT);throw e;}finally{clearTimeout(timer);download=null;}
}
async function remove(){
 canceled=true;download?.abort();
 // Durable revocation also stops a distinct waiting/installing worker instance.
 const c=await caches.open(CONTROL);await c.put(STATE,new Response(JSON.stringify({consent:null,removed:true}),{headers:{'content-type':'application/json'}}));
 if(installWork)await installWork.catch(()=>{});
 for(const name of await caches.keys())if(name.startsWith(PREFIX)&&name!==CONTROL)await caches.delete(name);
 await self.registration.unregister();return {ready:false};
}
self.addEventListener('install',event=>{installWork=install();event.waitUntil(installWork);});
self.addEventListener('activate',event=>event.waitUntil((async()=>{
 await ensure();if(!await complete(true))throw Error('Keine vollständige Offlinekopie.');
 await ensure();await self.clients.claim();
 // Old complete snapshots are retained if the new install failed before activation.
 for(const name of await caches.keys())if(name.startsWith(PREFIX+'snapshot-')&&name!==SNAPSHOT){await ensure();await caches.delete(name);}
})()));
self.addEventListener('message',event=>{
 const port=event.ports?.[0];if(!port)return;
 const action=event.data?.type==='REMOVE'?remove():event.data?.type==='STATUS'?(async()=>({ready:await complete(true),version:VERSION}))():Promise.reject(Error('Unbekannte Aktion.'));
 event.waitUntil(action.then(value=>port.postMessage({ok:true,...value})).catch(()=>port.postMessage({ok:false,ready:false,error:'Offline-Speicher konnte nicht bestätigt werden.'})));
});
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);if(event.request.method!=='GET'||url.origin!==self.location.origin)return;
 let key=url.href;
 if(event.request.mode==='navigate'&&(url.pathname===new URL(SCOPE).pathname||url.pathname===new URL('index.html',SCOPE).pathname))key=new URL('index.html',SCOPE).href;
 if(!ALLOWED.has(key))return;
 event.respondWith((async()=>{
  if(await complete()){const saved=await(await caches.open(SNAPSHOT)).match(key);if(saved){const s=await state();if(!canceled&&s?.removed===false)return saved;}}
  return fetch(event.request);
 })());
});
