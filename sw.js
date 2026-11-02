/* Generated: only public shell and authenticated ciphertext are cacheable. */
'use strict';
const FILES=[{"bytes":3059,"path":"index.html","sha256":"96cbda32bc1b9ee4ceaa5fe28126c1d167650d85b5543317b791a8ab9aab3837"},{"bytes":2319,"path":"shell.css","sha256":"fe93ddfca21d8a5762e6dde9ec1179a855204304c27109f1447e4617de532e3b"},{"bytes":9454,"path":"shell.mjs","sha256":"9da448c19d774459b6c39a1a4fd800e1d6c4de0c215ba2a4756efa3202ae9980"},{"bytes":9301,"path":"crypto.mjs","sha256":"04c9a48b09028b35aa02c015a54fa108e70e422d93e1d82c96e5f44225dffa8e"},{"bytes":275,"path":"manifest.webmanifest","sha256":"f50fc8e466ed3b01baaa6facffb293d49c6a17bfdc2d67478af4893a7a89e444"},{"bytes":31559,"path":"app-icon.png","sha256":"c9369397185f3c106dfc1d6fa8cb28b80f3c77189835476cbf9fc42ab578da3c"},{"bytes":2587,"path":"payload.json","sha256":"e03920619741df0bcd5a6c0311bee15142055ab8a2a10560a590fefb4e8c5be1"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0001.bin","sha256":"cbe89e7e5270a68e71f971e17475d289da2c009af52a46a6c6ee04870b5cac04"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0002.bin","sha256":"34fbcefbc93fe044fd685823b7b0727d5c82e0d86743405db690c5b573de1839"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0003.bin","sha256":"4003403db8f8f7aa4fd2c16754700899515a98999d1d9fbb23319e1534487ecf"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0004.bin","sha256":"0cd1921f280db09acd4749441a62898d2425e0157d8f47d95c6ec7d86d1f0263"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0005.bin","sha256":"c6cd4ca978f24a53cb5cb38137c8dae8f3214a1532a17d17f8be4d88920ff64c"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0006.bin","sha256":"f93fe5868c8b548ab99bef179744c29c217462619a1b9994fe72fdaa87570e27"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0007.bin","sha256":"b0b9d9b32e37cbeaf48fcdbd28fbcc31ff190920f103fd45f8c9a754a5c896d0"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0008.bin","sha256":"7ce3963988bad17e8836ba4f1afc9d1a8dd1b6db3a64dab52b090a0458295ed0"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0009.bin","sha256":"4c72b4c3ed44d49da2a452ce6432a6b0c63e58f4d7cc02ec54207cb13e40500d"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0010.bin","sha256":"2724a1850b14a04473421109bbd74872dfc55c84690788d988169452ed4abd81"},{"bytes":1048576,"path":"payload-3c30474625fa9446-0011.bin","sha256":"be7d30c3de05e1a11f779ff5f173e1d42f00c3dc512ada7528e45e72f431be27"},{"bytes":815704,"path":"payload-3c30474625fa9446-0012.bin","sha256":"355aa785c433bd75fa3a562dff7517922250f7c17d8bb9093b90886d8da87663"}],VERSION="bd7041ff3a3d25434909d9e0";
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
