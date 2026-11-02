/* Generated: only public shell and authenticated ciphertext are cacheable. */
'use strict';
const FILES=[{"bytes":6010,"path":"index.html","sha256":"63df28b6d27d1efab19d8e068c743c085196356e091bf53d312594ccd1f0cb7b"},{"bytes":4381,"path":"shell.css","sha256":"faaf0d6cd00d342c6e6d27fc20d9bd314360923807ade5cbb2e123755fcbf992"},{"bytes":12171,"path":"shell.mjs","sha256":"ccba8ccf3bf0d4294716c78a1583c0a04b8ed0e76515957c6dff1468a6eb25e1"},{"bytes":9301,"path":"crypto.mjs","sha256":"04c9a48b09028b35aa02c015a54fa108e70e422d93e1d82c96e5f44225dffa8e"},{"bytes":275,"path":"manifest.webmanifest","sha256":"f50fc8e466ed3b01baaa6facffb293d49c6a17bfdc2d67478af4893a7a89e444"},{"bytes":31559,"path":"app-icon.png","sha256":"c9369397185f3c106dfc1d6fa8cb28b80f3c77189835476cbf9fc42ab578da3c"},{"bytes":2757,"path":"payload.json","sha256":"d08f739d32e81dd64a150e4ee816e0aed310b6dd0cac8820d28782621c8b0ebb"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0001.bin","sha256":"7593a2fc087951a1ee7a883bea73de4ee3449866a2f3be3bab15b3bb664333df"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0002.bin","sha256":"9ec3c3c0820c26a18f36e3cfb6345f008c4366d06e95b1982a4ba66270c5076f"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0003.bin","sha256":"971c2d1a3c61b3f8e66319130bd68ba3ef976f7f4b4afbc195aa251eb1f106c7"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0004.bin","sha256":"09bbe9bbc82db09187a605233d5c5724e5e1fc29914177e86b77e27493198542"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0005.bin","sha256":"3e14206134125985a2330c7fea6de43436c303acf7a9c5d13645e1dee9d0890a"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0006.bin","sha256":"f591e4fef099622fa19c7f3d6961f8cf3cbe971e392ca5d417827e101e8fcedc"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0007.bin","sha256":"799e5d1fcdb57bcc955c06b00c5d0ba6ea11cb8f8596d2a847cc437fabba31dd"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0008.bin","sha256":"afc5c55212990b6aada330bf1413953cf74235e490576509bf9447edbffcf7ae"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0009.bin","sha256":"022978125ada82bffc115dfb7db5451e1b5821ead586f3d57c9e94b3cb1536b6"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0010.bin","sha256":"e59cb52e23c80397d96b8cce713a0574cc65fba41eff119801f11b78d25afc54"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0011.bin","sha256":"c2bb5939bf2df3f405338928b1317c20e8893d44b1718698a015d8057a20a2e0"},{"bytes":1048576,"path":"payload-2a7660712445fb20-0012.bin","sha256":"3812aa8a3af59e0f2465caee81fe03dafb2a05da38f142ee94f80b170b9729bf"},{"bytes":279233,"path":"payload-2a7660712445fb20-0013.bin","sha256":"9f6f774af80900fd2605fb84049d1e63764ba4a2f5c4b0c52847a80a72210fd6"}],VERSION="1678ef8209e27f83b4ffffbf";
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
