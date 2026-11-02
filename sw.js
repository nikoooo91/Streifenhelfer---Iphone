/* Generated: only public shell and authenticated ciphertext are cacheable. */
'use strict';
const FILES=[{"bytes":6010,"path":"index.html","sha256":"39134a2b87530b00bcc90541aa4d592694a4d790d43087ff587eeaf3ce1746c1"},{"bytes":4381,"path":"shell.css","sha256":"faaf0d6cd00d342c6e6d27fc20d9bd314360923807ade5cbb2e123755fcbf992"},{"bytes":12171,"path":"shell.mjs","sha256":"ccba8ccf3bf0d4294716c78a1583c0a04b8ed0e76515957c6dff1468a6eb25e1"},{"bytes":9301,"path":"crypto.mjs","sha256":"04c9a48b09028b35aa02c015a54fa108e70e422d93e1d82c96e5f44225dffa8e"},{"bytes":275,"path":"manifest.webmanifest","sha256":"f50fc8e466ed3b01baaa6facffb293d49c6a17bfdc2d67478af4893a7a89e444"},{"bytes":31559,"path":"app-icon.png","sha256":"c9369397185f3c106dfc1d6fa8cb28b80f3c77189835476cbf9fc42ab578da3c"},{"bytes":2587,"path":"payload.json","sha256":"4202151655e75e325e51b961f5ff08093d8147199d09b7c7b81bda9edbf908af"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0001.bin","sha256":"5844e5d37f70283beebeea32c3fcc137a1dd2c30e427567d28ed3ac884bc2ec6"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0002.bin","sha256":"ba4cadf368149cddffa1ed505847aff496dc7d6a1f884b49a5b016cec4b0c35c"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0003.bin","sha256":"fea2ff13bfb37a6c150e9272ed1fb549a887b0668b9cf88f0ce74bde3af1c38d"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0004.bin","sha256":"99be1e50ad2d69942975b472b8d32ddbe200232821198929ad75235f3fdea943"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0005.bin","sha256":"cff5612379c05af6413d6cdf2fdfcd03725fdaa58786173bb24f83e89fb6cc8a"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0006.bin","sha256":"1a8c4e4aa4190d4c54c51a726946080aa28c821a89dfbb035e85a7a79c50480e"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0007.bin","sha256":"56fd343c275ca52570ac2044e43dd26abc079cfaff040a6aa9aa85822a85eaa2"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0008.bin","sha256":"026e4438b6d57f9948aaf8b195b95cd7a3214dd0c808ff31dbd38e0e81073cd9"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0009.bin","sha256":"9db0fe6af383065bd69c7382ed39a6a22e31d40addfc3c01aefdf2938e03aeef"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0010.bin","sha256":"ab13a23521bb19db9f8fd279a0ea9776b890c35f60edda663ca28e0869063191"},{"bytes":1048576,"path":"payload-fb51662913824fb2-0011.bin","sha256":"cab6c56beaa81eefe740d4e3b68494958a48d007d9c09861acb60e5371b380ad"},{"bytes":808535,"path":"payload-fb51662913824fb2-0012.bin","sha256":"81e5c6f0c548c5fedb3c3b61bd0448c4005ba49badb10071a6d5e99a46a1d03d"}],VERSION="41ed8013cbda8381b4f013ff";
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
