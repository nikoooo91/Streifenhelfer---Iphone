import {decryptPayload,validateManifest,MAX_UNCOMPRESSED_BYTES} from './crypto.mjs';
const $=id=>document.getElementById(id);
let generation=0,controller=null,frame=null,objectURL=null,offlineBusy=false,offlineGeneration=0,removing=false;
const offlineScope=new URL('./',location.href).href;
const offlinePrefix='streifenhelfer-encrypted-'+encodeURIComponent(offlineScope)+'-';
const offlineControl=offlinePrefix+'control',offlineState=new URL('__offline-control',offlineScope).href;
let offlineMutation=Promise.resolve();
function offlineExclusive(fn){const next=offlineMutation.then(fn,fn);offlineMutation=next.catch(()=>{});return next;}
async function setConsent(consent){const c=await caches.open(offlineControl);await c.put(offlineState,new Response(JSON.stringify({consent,removed:!consent}),{headers:{'content-type':'application/json'}}));}
const status=t=>{$('status').textContent=t;$('reader-status').textContent=t;};
function lock(message='Gesperrt. Zum Öffnen Zugangsschlüssel eingeben.'){
 generation++;controller?.abort();controller=null;
 $('access-key').value='';frame?.remove();frame=null;
 if(objectURL){URL.revokeObjectURL(objectURL);objectURL=null;}
 $('reader').hidden=true;$('gate').hidden=false;$('unlock').disabled=false;status(message);
}
async function load(url,signal){const r=await fetch(url,{signal,credentials:'omit',referrerPolicy:'no-referrer',cache:'no-cache'});if(!r.ok)throw Error('Die App-Dateien sind nicht vollständig erreichbar. Online neu öffnen oder Offlinekopie speichern.');return r;}
async function boundedBytes(response,limit){
 const reader=response.body?.getReader();if(!reader)throw Error('Leere App-Datei.');
 const pieces=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw Error('App-Datei überschreitet die erlaubte Größe.');pieces.push(value);}}
 catch(e){await reader.cancel().catch(()=>{});throw e;}
 const result=new Uint8Array(size);let offset=0;for(const p of pieces){result.set(p,offset);offset+=p.length;}return result;
}
export async function expand(gzip){
 if(!globalThis.DecompressionStream)throw Error('Bitte iOS und Safari aktualisieren. Diese Version unterstützt die Entschlüsselung nicht vollständig.');
 const reader=new Blob([gzip]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();let size=0,parts=[];
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX_UNCOMPRESSED_BYTES)throw Error('App-Paket zu groß.');parts.push(value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}
 return new Blob(parts,{type:'text/html;charset=utf-8'});
}
$('unlock-form').addEventListener('submit',async e=>{
 e.preventDefault();if($('unlock').disabled)return;
 if(!globalThis.crypto?.subtle){status('Bitte den HTTPS-Link in Safari öffnen. In dieser Vorschau ist die Entschlüsselung nicht verfügbar.');return;}
 let password=$('access-key').value.trim();$('access-key').value='';
 if(!password)return;const own=++generation;controller?.abort();const abort=new AbortController();controller=abort;
 $('unlock').disabled=true;status('Verschlüsselte App wird geladen …');
 try{
  const manifest=validateManifest(JSON.parse(new TextDecoder().decode(await boundedBytes(await load('./payload.json',abort.signal),65536))));let done=0;
  const compressed=await decryptPayload(manifest,password,async chunk=>{
   if(own!==generation)throw new DOMException('Abgebrochen','AbortError');
   const response=await load('./'+chunk.name,abort.signal);const bytes=await boundedBytes(response,chunk.size);
   done++;if(own===generation)status('App wird geladen · '+done+' / '+manifest.chunks.length);return bytes;
  });password='';if(own!==generation)return;status('App wird geöffnet …');
  const html=await expand(compressed);compressed.fill(0);if(own!==generation)return;
  objectURL=URL.createObjectURL(html);frame=document.createElement('iframe');frame.title='Streifenhelfer';
  frame.setAttribute('sandbox','allow-scripts allow-popups allow-popups-to-escape-sandbox');frame.referrerPolicy='no-referrer';
  const currentURL=objectURL;frame.addEventListener('load',()=>{URL.revokeObjectURL(currentURL);if(objectURL===currentURL)objectURL=null;},{once:true});
  frame.src=objectURL;$('frame-host').replaceChildren(frame);$('gate').hidden=true;$('reader').hidden=false;status('Streifenhelfer');
 }catch(error){if(own===generation)status(error.name==='AbortError'?'Öffnen abgebrochen.':error.message?.startsWith('Die App-Dateien')?error.message:'Öffnen fehlgeschlagen. Zugangsschlüssel und Verbindung prüfen. Bei unvollständiger Offlinekopie diese online erneuern.');}
 finally{password='';if(own===generation){$('unlock').disabled=false;controller=null;}}
});
$('lock').addEventListener('click',()=>lock());
addEventListener('pagehide',()=>lock());
addEventListener('pageshow',e=>{if(e.persisted)lock();});
document.addEventListener('visibilitychange',()=>{if(document.hidden&&(frame||controller))lock();});
function offlineText(text){$('offline-status').textContent=text;$('reader-status').textContent=text;frame?.contentWindow?.postMessage({type:'SH_OFFLINE_STATUS',text},'*');}
async function offline(){
 if(offlineBusy||removing)return;offlineBusy=true;$('offline').disabled=true;const own=++offlineGeneration;
 try{
  if(!('serviceWorker' in navigator)||!isSecureContext)throw Error('Offlinebetrieb benötigt den HTTPS-Link in Safari.');
  offlineText('Verschlüsselte Offlinekopie wird gespeichert …');
  const consent=Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
  await offlineExclusive(async()=>{if(own!==offlineGeneration)throw Error('Speichern abgebrochen.');await setConsent(consent);});
  if(own!==offlineGeneration)return;
  const reg=await navigator.serviceWorker.register('./sw.js?consent='+consent,{scope:'./',updateViaCache:'none'});
  if(own!==offlineGeneration){await Promise.allSettled([...new Set([reg.installing,reg.waiting,reg.active].filter(Boolean))].map(w=>workerMessage(w,'REMOVE')));await reg.unregister();return;}
  const worker=reg.installing||reg.waiting||reg.active;
  if(!worker)throw Error('Offline-Dienst nicht verfügbar.');
  if(worker.state!=='activated')await new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>reject(Error('Speichern dauert zu lange. Online erneut versuchen.')),180000);
   function check(){if(worker.state==='activated'){clearTimeout(timer);worker.removeEventListener('statechange',check);resolve();}else if(worker.state==='redundant'){clearTimeout(timer);worker.removeEventListener('statechange',check);reject(Error('Offlinekopie nicht vollständig. Verbindung und freien Speicher prüfen.'));}}
   worker.addEventListener('statechange',check);check();
  });
  if(own!==offlineGeneration)return;
  const answer=await workerMessage(reg.active||worker,'STATUS');if(own!==offlineGeneration)return;if(!answer.ready)throw Error('Offlinekopie nicht vollständig.');
  offlineText('Offlinekopie gespeichert. Bitte im Flugmodus neu öffnen und entsperren.');
 }catch(e){if(own===offlineGeneration)offlineText(e.message);}finally{offlineBusy=false;$('offline').disabled=removing;}
}
function workerMessage(worker,type){return new Promise((resolve,reject)=>{const channel=new MessageChannel();const timer=setTimeout(()=>{channel.port1.close();reject(Error('Offline-Dienst antwortet nicht.'));},10000);channel.port1.onmessage=e=>{clearTimeout(timer);channel.port1.close();e.data?.ok?resolve(e.data):reject(Error(e.data?.error||'Offline-Dienst nicht verfügbar.'));};worker.postMessage({type},[channel.port2]);});}
$('offline').addEventListener('click',offline);
$('remove').addEventListener('click',async()=>{
 if(removing)return;removing=true;offlineGeneration++;lock();$('remove').disabled=true;$('offline').disabled=true;
 try{
  await offlineExclusive(()=>setConsent(null));
  const regs=await navigator.serviceWorker?.getRegistrations()||[];
  for(const reg of regs){if(reg.scope===offlineScope){
   const workers=[...new Set([reg.active,reg.waiting,reg.installing].filter(Boolean))];
   await Promise.allSettled(workers.map(worker=>workerMessage(worker,'REMOVE')));await reg.unregister();
  }}
  if('caches' in globalThis)for(const key of await caches.keys())if(key.startsWith(offlinePrefix)&&key!==offlineControl)await caches.delete(key);
  offlineText('Offlinekopie entfernt.');
 }catch(e){offlineText('Entfernen nicht bestätigt: '+e.message);}finally{removing=false;$('remove').disabled=false;$('offline').disabled=offlineBusy;}
});
addEventListener('message',e=>{if(!frame||e.source!==frame.contentWindow)return;if(e.data?.type==='SH_LOCK')lock();if(e.data?.type==='SH_OFFLINE')offline();});
if('serviceWorker' in navigator){const own=offlineGeneration;navigator.serviceWorker.getRegistration('./').then(async reg=>{if(reg?.active){const s=await workerMessage(reg.active,'STATUS');if(own===offlineGeneration)offlineText(s.ready?'Verschlüsselte Offlinekopie vorhanden.':'Keine vollständige Offlinekopie.');}else if(own===offlineGeneration)offlineText('Noch keine Offlinekopie gespeichert.');}).catch(()=>{if(own===offlineGeneration)offlineText('Offline-Status nicht verfügbar.');});}
function viewport(){if(window.visualViewport&&Math.abs(visualViewport.scale-1)<.05)document.documentElement.style.setProperty('--sh-shell-height',visualViewport.height+'px');}window.visualViewport?.addEventListener('resize',viewport);viewport();
