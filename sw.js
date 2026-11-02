/* Generated: only public shell and authenticated ciphertext are cacheable. */
'use strict';
const FILES=[{"bytes":6010,"path":"index.html","sha256":"d67afbbfe63ab2f78f175d81f985980397cda007318a5c429f0718e9c1777d96"},{"bytes":4381,"path":"shell.css","sha256":"faaf0d6cd00d342c6e6d27fc20d9bd314360923807ade5cbb2e123755fcbf992"},{"bytes":12171,"path":"shell.mjs","sha256":"ccba8ccf3bf0d4294716c78a1583c0a04b8ed0e76515957c6dff1468a6eb25e1"},{"bytes":9301,"path":"crypto.mjs","sha256":"04c9a48b09028b35aa02c015a54fa108e70e422d93e1d82c96e5f44225dffa8e"},{"bytes":275,"path":"manifest.webmanifest","sha256":"f50fc8e466ed3b01baaa6facffb293d49c6a17bfdc2d67478af4893a7a89e444"},{"bytes":31559,"path":"app-icon.png","sha256":"c9369397185f3c106dfc1d6fa8cb28b80f3c77189835476cbf9fc42ab578da3c"},{"bytes":2757,"path":"payload.json","sha256":"42616b28db4c5a5b1e29da16153d7d1db8e18010b7c73ecd2e477aba6a564461"},{"bytes":1048576,"path":"payload-b280be9144871363-0001.bin","sha256":"1bb9ae27c5491cc39a450766799d67c760457d3f8080ce5e8b07eeac79d4c6cc"},{"bytes":1048576,"path":"payload-b280be9144871363-0002.bin","sha256":"9899b322dc6e68508db1068e638c2b179fe05b0c0b01e05c30e6cc4c5f41ecfd"},{"bytes":1048576,"path":"payload-b280be9144871363-0003.bin","sha256":"48bce5aef14369b0f32a7f21b2ddeb3a1a134c18688257e868b4234d899636d6"},{"bytes":1048576,"path":"payload-b280be9144871363-0004.bin","sha256":"e50281f8a859f2623c16f688c539e5b8f7646ee2cda5bcd5cbdfaceed9a53577"},{"bytes":1048576,"path":"payload-b280be9144871363-0005.bin","sha256":"b9d58b9ded2d839451e8f96f83be38c36bbe5e57173924f846d1f685752a1f3c"},{"bytes":1048576,"path":"payload-b280be9144871363-0006.bin","sha256":"0970b927c0350aa5e537182c60baed7a598aeca31ac75fc3f5f31f6221be06a4"},{"bytes":1048576,"path":"payload-b280be9144871363-0007.bin","sha256":"12b3fd083bacafb2ad5f1c89c15742539b584282497b16732687bf376d2751e6"},{"bytes":1048576,"path":"payload-b280be9144871363-0008.bin","sha256":"32a481af2c083c2d81d879ef0a2160ad8a4edf9614d3fddf67333a115362e551"},{"bytes":1048576,"path":"payload-b280be9144871363-0009.bin","sha256":"0b2174fbc96287f9d3218c22bac0398fed027bfe21b31d1c39194239960ef8e0"},{"bytes":1048576,"path":"payload-b280be9144871363-0010.bin","sha256":"904a18fbd12631be663a0829bc7b2ebc826b0c7e520e0035fde4d8c8431c9982"},{"bytes":1048576,"path":"payload-b280be9144871363-0011.bin","sha256":"49398cc6f6c7f3a4cf983c5194b11a1f843f7a502d9b739c40c6051721b04fce"},{"bytes":1048576,"path":"payload-b280be9144871363-0012.bin","sha256":"f39d87618cfeed450e0df10b85bd2c9bf23c95d8a022c8a65e258cc9aa2b9615"},{"bytes":243399,"path":"payload-b280be9144871363-0013.bin","sha256":"5cd2be79e010de44e321e827d5aee6b35ca3efaaa65afc6f10ad6d58fc4d8d32"}],VERSION="bf3748fc1d707d81c89e977e";
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
