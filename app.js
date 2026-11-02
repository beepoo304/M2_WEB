const tabButtons = [...document.querySelectorAll('.nav-item')];
const screen = document.getElementById('screen');
const liveState = { packets: [], loading: false, error: '', lastSuccess: 0, selected: null, details: null, detailsLoading: false, detailsError: '' };
// Mirrors M²'s observation-match cache: a packet is rechecked only if its
// observation count changed or its cached route analysis is older than 30 s.
const observationMatchCache = new Map();
const OBSERVATION_CACHE_MS = 30_000;
const MAX_OBSERVATION_REQUESTS = 6;
const gpsDirectoryCache = new Map();
const GPS_DIRECTORY_CACHE_MS = 3_600_000;
const KEY_STORAGE = 'm2-web-tracked-keys-v1';
const MY_LOG_STORAGE = 'm2-web-own-traffic-log-v1';
const CHANNEL_STORAGE = 'm2-web-channels-v1';
const ACTIVE_TAB_STORAGE = 'm2-web-active-tab-v1';
const API_STORAGE = 'm2-web-api-sources-v1';
const REFRESH_STORAGE = 'm2-web-refresh-interval-v1';
const REFRESH_OPTIONS = [
  ...Array.from({length:8},(_,i)=>(i+3)*1000),
  ...Array.from({length:9},(_,i)=>(i+3)*5000),
  ...Array.from({length:59},(_,i)=>(i+1)*60000),
  60*60000
];
let refreshIntervalMs = loadRefreshInterval();
let nextRefreshAt = Date.now() + refreshIntervalMs;
let trackedKeys = loadTrackedKeys();
let myLogPackets = loadMyLogPackets();
let savedChannels = loadChannels();
let apiSources = loadApiSources();
let activeApiSource = apiSources[0];
const nodeInfoCache = new Map();
const labels = {0:'REQUEST',1:'RESPONSE',2:'DIRECT MSG',3:'ACK',4:'ADVERT',5:'CHANNEL MSG',6:'GROUP DATA',7:'ANON REQ',8:'PATH',9:'TRACE',10:'MULTIPART',11:'CONTROL',15:'RAW CUSTOM'};
const trackedRelations = { source:'SOURCE', end:'LAST RECORDED HOP', route:'IN ROUTE', observer:'REPORTED BY', reply:'REPLY TO' };

function safeText(value, fallback = '—') { return value == null || value === '' ? fallback : String(value); }
function parseDecoded(packet) {
  if (packet._decoded && typeof packet._decoded === 'object') return packet._decoded;
  try { packet._decoded = typeof packet.decoded_json === 'string' ? JSON.parse(packet.decoded_json) : (packet.decoded_json || {}); }
  catch { packet._decoded = {}; }
  return packet._decoded;
}
function packetType(packet) { return labels[Number(packet.payload_type)] || `UNKNOWN ${safeText(packet.payload_type, '?')}`; }
function packetTime(packet) {
  const date = new Date(packet.timestamp || packet.first_seen);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('pl-PL', { timeZone:'Europe/Warsaw', hour:'2-digit', minute:'2-digit', second:'2-digit' }).format(date);
}
function relativeAge(packet) {
  const stamp = new Date(packet.timestamp || packet.first_seen).getTime();
  if (!Number.isFinite(stamp)) return 'time unavailable';
  const seconds = Math.max(0, Math.floor((Date.now() - stamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s ago`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m ago`;
}
function packetSummary(packet) {
  const decoded = parseDecoded(packet), type = Number(packet.payload_type);
  if (type === 5) return `${safeText(decoded.channel, 'Private channel')} · ${safeText(decoded.text, 'Message content unavailable')}`;
  if (type === 4) return safeText(decoded.name, 'Node advertisement');
  if (type === 2) return 'Encrypted direct message';
  if (type === 8) return 'Path information';
  if (type === 0) return 'Request';
  if (type === 1) return 'Response';
  if (type === 3) return 'Acknowledgement';
  if (type === 11) return 'Control packet';
  return `${packet.raw_hex ? packet.raw_hex.length / 2 : 0} B`;
}
function liveIdentityLabel(packet) {
  const decoded=parseDecoded(packet), flags=decoded.flags||{};
  const role=flags.repeater?'REPEATER':flags.chat?'COMPANION':flags.room?'ROOM SERVER':flags.sensor?'SENSOR':'UNKNOWN';
  const sender=String(decoded.sender||'').trim();
  const node=String(decoded.name||'').trim();
  if(sender)return `Sender: ${sender}`;
  if(node)return `${role}: ${node}`;
  return `OBSERVER: ${packet.observer_name||'Unknown observer'}`;
}
function liveIdentityMarkup(packet) {
  const decoded=parseDecoded(packet),flags=decoded.flags||{};
  const sender=String(decoded.sender||'').trim();
  if(sender)return escapeHtml(`Sender: ${sender}`);
  const role=flags.repeater?'REPEATER':flags.chat?'COMPANION':flags.room?'ROOM SERVER':flags.sensor?'SENSOR':'UNKNOWN';
  const name=String(decoded.name||'').trim();
  if(role==='COMPANION')return `<span class="companion-role">COMPANION</span>: ${escapeHtml(name||'Unknown')}`;
  if(name)return escapeHtml(`${role}: ${name}`);
  return escapeHtml(`OBSERVER: ${packet.observer_name||'Unknown observer'}`);
}
function renderTrackedText(value) {
  const text=String(value??'');
  const names=[...new Set(trackedKeys.map(item=>item.name).filter(Boolean))].sort((a,b)=>b.length-a.length);
  if(!names.length)return escapeHtml(text);
  const pattern=new RegExp(`@?\\[?(?:${names.map(name=>name.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&')).join('|')})\\]?`,'giu');
  let output='',cursor=0,match;
  while((match=pattern.exec(text))){
    const start=match.index,end=start+match[0].length;
    const before=start?text[start-1]:'';const after=text[end]||'';
    if((before&&/[\p{L}\p{N}_]/u.test(before))||(after&&/[\p{L}\p{N}_]/u.test(after)))continue;
    output+=escapeHtml(text.slice(cursor,start))+`<strong class="tracked-name-highlight">${escapeHtml(match[0])}</strong>`;cursor=end;
  }
  return output+escapeHtml(text.slice(cursor));
}
function packetPath(packet) {
  const raw=Array.isArray(packet._parsedPath) ? packet._parsedPath : (()=>{try{return JSON.parse(packet.path_json||'[]')}catch{return[]}})();
  // M² keeps every API path entry intact. In particular, adjacent 1-byte
  // entries must never be merged: doing so corrupts a trace route.
  return Array.isArray(raw) ? raw.map(hop=>String(hop||'').trim().toUpperCase()) : [];
}
function pathSummary(packet) {
  const path = packetPath(packet);
  if (!path.length) return 'direct';
  if (path.some(hop => String(hop).length === 2)) return '1-byte route';
  return `${path.length} hops`;
}
function keyName(key) { return trackedKeys.find(item=>item.key.toLowerCase()===String(key||'').toLowerCase())?.name || `${String(key||'').slice(0,4).toUpperCase()}…`; }
function reliableHash(value) { const text=String(value||'').trim();return text.length>=4&&text.length<=64&&text.length%2===0&&/^[a-f\d]+$/i.test(text); }
function uniqueKeyForHash(hash) { if(!reliableHash(hash))return null;const found=trackedKeys.filter(item=>item.key.toLowerCase().startsWith(String(hash).toLowerCase()));return found.length===1?found[0]:null; }
function exactTrackedKey(value) { const text=String(value||'').trim().toLowerCase();return /^[a-f\d]{64}$/i.test(text)?trackedKeys.find(item=>item.key.toLowerCase()===text)||null:null; }
function uniqueNamedKeys(...names) { const normalized=names.map(name=>String(name||'').trim().toLowerCase()).filter(Boolean);const found=trackedKeys.filter(item=>item.name&&normalized.includes(item.name.trim().toLowerCase()));return found.length===1?found:[]; }
function mentionedTrackedKeys(text) { const message=String(text||'').toLowerCase();return trackedKeys.filter(item=>[item.name,item.key.slice(0,4)].some(raw=>{const value=String(raw||'').trim().toLowerCase();if(!value)return false;const escaped=value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return new RegExp(`(?<![\\p{L}\\p{N}_])@(?:\\[${escaped}\\]|${escaped})(?![\\p{L}\\p{N}_])`,'u').test(message);})); }
function relationMatches(packet) {
  const decoded=parseDecoded(packet),path=packetPath(packet),resolved=Array.isArray(packet.resolved_path)?packet.resolved_path:[];
  const out=[],add=(relation,item)=>{if(item&&!out.some(match=>match.relation===relation&&match.key===item.key))out.push({relation,key:item.key,name:item.name});};
  const trackable=path.every(reliableHash);
  if(trackable){
    const source=exactTrackedKey(decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey);
    const sourceHash=uniqueKeyForHash(decoded.srcHash);
    const destination=exactTrackedKey(decoded.destKey)||uniqueKeyForHash(decoded.destHash);
    for(const item of [source,sourceHash,...uniqueNamedKeys(decoded.sender,decoded.name)])add(trackedRelations.source,item);
    // M² counts a decoded destination as own traffic, but does not render it as a reply label.
    add('DESTINATION',destination);
    path.forEach((hop,index)=>{
      const resolvedKey=String(resolved[index]||'').toLowerCase();
      const item=resolvedKey.startsWith(String(hop).toLowerCase())?exactTrackedKey(resolvedKey):uniqueKeyForHash(hop);
      add(index===path.length-1?trackedRelations.end:trackedRelations.route,item);
    });
    add(trackedRelations.observer,exactTrackedKey(packet.observer_id));
    mentionedTrackedKeys(decoded.text).forEach(item=>add(trackedRelations.reply,item));
  }
  if(Number(packet.payload_type)===9&&path.every(hop=>reliableHash(hop))&&path.some(hop=>uniqueKeyForHash(hop)))
    path.forEach(hop=>add(trackedRelations.route,uniqueKeyForHash(hop)));
  return out;
}
function matchesForPacket(packet) { return relationMatches(packet).filter(match=>match.relation!=='DESTINATION'); }
function mergeMatches(...lists) {
  const result=[];
  lists.flat().forEach(match=>{
    if(match && match.relation !== 'DESTINATION' && !result.some(item=>item.relation===match.relation && item.key.toLowerCase()===match.key.toLowerCase())) result.push(match);
  });
  return result;
}
function observationRoutes(data) {
  return (Array.isArray(data?.observations)?data.observations:[]).map(observation=>{
    let path=[];
    try { path=JSON.parse(observation.path_json||'[]'); } catch {}
    return { path:Array.isArray(path)?path:[], resolved:Array.isArray(observation.resolved_path)?observation.resolved_path:[], observer:observation };
  });
}
function enhancedMatches(packet) {
  const cached=observationMatchCache.get(String(packet.id));
  const routeMatches=cached?.data?.loadSucceeded ? observationRoutes(cached.data).filter(route=>route.path.every(reliableHash)).map(route=>relationMatches({...packet,path_json:JSON.stringify(route.path),resolved_path:route.resolved,observer_id:route.observer.observer_id})) : [];
  return mergeMatches(matchesForPacket(packet),routeMatches);
}
function routeEventExists(packet, route, key) {
  if(!route.path.every(reliableHash)) return false;
  const relations=relationMatches({...packet,path_json:JSON.stringify(route.path),resolved_path:route.resolved,observer_id:route.observer.observer_id});
  const own=relations.filter(match=>match.key.toLowerCase()===String(key).toLowerCase());
  const has=relation=>own.some(match=>match.relation===relation);
  const accepted=has(trackedRelations.source)||has(trackedRelations.end)||has(trackedRelations.route)||has(trackedRelations.observer)||(has(trackedRelations.reply)&&relations.some(match=>match.relation===trackedRelations.observer));
  if(!accepted)return false;
  const path=[...route.path];
  const sourceMatch=own.find(match=>match.relation===trackedRelations.source);
  if(sourceMatch && !sourceMatch.key.toLowerCase().startsWith(String(path[0]||'').toLowerCase())) path.unshift(sourceMatch.key.slice(0,4).toUpperCase());
  const observerKey=String(route.observer.observer_id||'');
  const observerSelected=has(trackedRelations.observer);
  if((observerSelected || (sourceMatch&&reliableHash(observerKey))) && !observerKey.toLowerCase().startsWith(String(path.at(-1)||'').toLowerCase())) path.push(observerKey.slice(0,4).toUpperCase());
  return path.length>=2;
}
function replyHasNoRoute(packet, key) {
  const cached=observationMatchCache.get(String(packet.id));
  if(!cached?.data?.loadSucceeded)return false;
  return !observationRoutes(cached.data).some(route=>routeEventExists(packet,route,key));
}
function hasValidGps(node) {
  const lat=Number(node?.lat), lon=Number(node?.lon);
  return Number.isFinite(lat)&&Number.isFinite(lon)&&lat>=-90&&lat<=90&&lon>=-180&&lon<=180&&!(Math.abs(lat)<0.01&&Math.abs(lon)<0.01);
}
function confirmedMissingGps(hash, resolvedKey='') {
  const directory=gpsDirectoryCache.get(activeApiSource)?.nodes||[];
  if(!reliableHash(hash))return false;
  const candidates=directory.filter(node=>String(node.public_key||'').toLowerCase().startsWith(String(hash).toLowerCase()));
  const node=resolvedKey ? candidates.filter(candidate=>String(candidate.public_key||'').toLowerCase()===String(resolvedKey).toLowerCase())[0] : candidates.length===1?candidates[0]:null;
  return !!node && String(node.role||'').toLowerCase()==='repeater' && !hasValidGps(node);
}
function missingGpsHashes(packet) {
  const cached=observationMatchCache.get(String(packet.id));
  if(!cached?.data?.loadSucceeded)return [];
  const result=[];
  observationRoutes(cached.data).forEach(route=>route.path.forEach((hash,index)=>{
    const resolved=route.resolved[index]||'';
    const label=String(hash).slice(0,4).toUpperCase();
    if(confirmedMissingGps(hash,resolved)&&!result.includes(label))result.push(label);
  }));
  return result;
}
function packetAccent(packet,matches) {
  const path=packetPath(packet);
  if(path.some(hop=>String(hop).length===2&&/^[a-f\d]{2}$/i.test(String(hop))))return 'packet-one-byte';
  if(matches.some(match=>match.relation!==trackedRelations.reply))return 'packet-own';
  return '';
}
function loadTrackedKeys() {
  try {
    const parsed=JSON.parse(sessionStorage.getItem(KEY_STORAGE)||'[]');
    const now=Date.now();
    return Array.isArray(parsed) ? parsed.filter(item=>item&&/^[a-f\d]{64}$/i.test(item.key||'')).map(item=>({
      key:item.key.toUpperCase(),
      name:String(item.name||'').trim(),
      counterStartedAt:Number.isFinite(Number(item.counterStartedAt)) ? Number(item.counterStartedAt) : now,
      packetCount:Math.max(0,Number.parseInt(item.packetCount,10)||0),
      seenPacketIds:Array.isArray(item.seenPacketIds) ? item.seenPacketIds.filter(value=>typeof value==='string').slice(-2000) : []
    })) : [];
  }
  catch { return []; }
}
function saveTrackedKeys() { sessionStorage.setItem(KEY_STORAGE,JSON.stringify(trackedKeys)); }
function loadMyLogPackets() { try { const value=JSON.parse(sessionStorage.getItem(MY_LOG_STORAGE)||'[]'); return Array.isArray(value)?value.slice(0,250):[]; } catch { return []; } }
function saveMyLogPackets() { sessionStorage.setItem(MY_LOG_STORAGE,JSON.stringify(myLogPackets.slice(0,250))); }
function loadChannels() { try { const value=JSON.parse(sessionStorage.getItem(CHANNEL_STORAGE)||'[]'); return Array.isArray(value)?value.filter(item=>typeof item?.name==='string').slice(0,50):[]; } catch { return []; } }
function saveChannels() { sessionStorage.setItem(CHANNEL_STORAGE,JSON.stringify(savedChannels.slice(0,50))); }
function updateMyLog(packets) {
  const related=(Array.isArray(packets)?packets:[]).filter(packet=>enhancedMatches(packet).length>0);
  if(!related.length)return;
  const byId=new Map(myLogPackets.map(packet=>[String(packet.id),packet]));
  related.forEach(packet=>byId.set(String(packet.id),packet));
  myLogPackets=[...byId.values()].sort((a,b)=>new Date(b.timestamp||b.first_seen)-new Date(a.timestamp||a.first_seen)).slice(0,250);
  saveMyLogPackets();
}
function packetIdentity(packet) {
  const hash=String(packet.hash||'').trim().toLowerCase();
  return hash ? `hash#${hash}` : `raw#${Number(packet.payload_type)||0}#${String(packet.timestamp||'')}#${String(packet.raw_hex||'').trim().toLowerCase()}`;
}
function packetEpoch(packet) {
  const value=Date.parse(packet.timestamp||packet.first_seen||'');
  return Number.isFinite(value) ? value : 0;
}
function recordTrackedPacketCounters(packets) {
  let changed=false;
  trackedKeys.forEach(item=>{
    const seen=new Set(item.seenPacketIds||[]);
    const additions=(Array.isArray(packets)?packets:[]).filter(packet=>{
      const identity=packetIdentity(packet);
      return !seen.has(identity) && packetEpoch(packet)>=item.counterStartedAt && enhancedMatches(packet).some(match=>match.key.toLowerCase()===item.key.toLowerCase());
    });
    if(!additions.length)return;
    additions.forEach(packet=>seen.add(packetIdentity(packet)));
    item.packetCount=(item.packetCount||0)+additions.length;
    item.seenPacketIds=[...seen].slice(-2000);
    changed=true;
  });
  if(changed)saveTrackedKeys();
  return changed;
}
// Kept for the Settings template; the value now comes from the session counter,
// not from the currently loaded 250-packet window.
function packetCountForTrackedKey(key) {
  return trackedKeys.find(item=>item.key.toLowerCase()===String(key||'').toLowerCase())?.packetCount || 0;
}
function formatCounterStart(value) {
  const time=Number(value);
  if(!Number.isFinite(time)||time<=0)return '—';
  return new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Warsaw',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}).format(time);
}
function normalizeApiSource(value) {
  try { const url=new URL(/^https?:\/\//i.test(value.trim())?value.trim():`https://${value.trim()}`); if(url.protocol!=='https:'||!url.hostname.includes('.'))return null;url.hash='';url.search='';return url.toString().replace(/\/$/,''); } catch { return null; }
}
function loadApiSources() {
  try { const saved=JSON.parse(sessionStorage.getItem(API_STORAGE)||'null'); if(Array.isArray(saved)){const clean=saved.map(normalizeApiSource).filter(Boolean);if(clean.length)return [...new Set(clean)];} } catch {}
  return ['https://live.meshcorekk.xyz'];
}
function saveApiSources() { sessionStorage.setItem(API_STORAGE,JSON.stringify(apiSources)); }
function loadRefreshInterval() {
  try { const saved=Number(sessionStorage.getItem(REFRESH_STORAGE));if(REFRESH_OPTIONS.includes(saved))return saved; } catch {}
  return 3000;
}
function formatRefreshInterval(value) {
  if(value<60000)return `${value/1000} seconds`;
  if(value===3600000)return '1 hour';
  const minutes=value/60000;
  return `${minutes} minute${minutes===1?'':'s'}`;
}
function sourceLabel(source) { try{return new URL(source).host;}catch{return source;} }
function apiProxyUrl(resource, params={}, source=activeApiSource) {
  const query=new URLSearchParams({resource,...params,source});
  return `/api.php?${query.toString()}`;
}
function nodeInfoDate(value) {
  const time=Date.parse(value||'');
  return Number.isFinite(time) ? new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Warsaw',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(time) : '—';
}
function metric(value, digits=2) { const number=Number(value); return Number.isFinite(number) ? number.toFixed(digits) : '—'; }
function closeNodeInfo() { document.querySelector('.node-info-backdrop')?.remove(); }
function showNodeInfo(item, data, loading=false, error='') {
  closeNodeInfo();
  const node=data?.node||{},stats=data?.stats||{},neighbours=Array.isArray(data?.neighbours)?data.neighbours:[];
  const body=loading ? '<p class="details-loading">Loading RPT information and recorded neighbours…</p>' : error ? `<p class="details-error">${escapeHtml(error)}</p>` : `<section class="node-info-grid"><div><span>ROLE</span><b>${escapeHtml(node.role||'—')}</b></div><div><span>LAST HEARD</span><b>${escapeHtml(nodeInfoDate(node.last_heard||node.last_seen))}</b></div><div><span>USEFULNESS</span><b>${escapeHtml(metric(node.usefulness_score))}${node.usefulness_grade?` · ${escapeHtml(node.usefulness_grade)}`:''}</b></div><div><span>TRAFFIC SHARE</span><b>${escapeHtml(metric(node.traffic_share_score))}</b></div><div><span>BRIDGE SCORE</span><b>${escapeHtml(metric(node.bridge_score))}</b></div><div><span>COVERAGE</span><b>${escapeHtml(metric(node.coverage_score))}</b></div><div><span>REDUNDANCY</span><b>${escapeHtml(metric(node.redundancy_score))}</b></div><div><span>FIRST SEEN</span><b>${escapeHtml(nodeInfoDate(node.first_seen))}</b></div><div><span>TOTAL PACKETS</span><b>${Number(stats.totalPackets||0).toLocaleString('en-US')}</b></div><div><span>PACKETS TODAY</span><b>${Number(stats.packetsToday||0).toLocaleString('en-US')}</b></div><div><span>AVG. SNR</span><b>${stats.avgSnr==null?'—':`${metric(stats.avgSnr,1)} dB`}</b></div><div><span>AVG. HOPS</span><b>${stats.avgHops==null?'—':metric(stats.avgHops,1)}</b></div></section><section class="neighbour-list"><h3>RECORDED NEIGHBOURS · ${neighbours.length}</h3>${neighbours.length?neighbours.map(neighbour=>`<div><code>${escapeHtml(neighbour.hash)}</code><b>${escapeHtml(neighbour.name)}</b><span>${Number(neighbour.count||0)} routes</span></div>`).join(''):'<p>No reliable neighbour route was found.</p>'}</section>`;
  document.body.insertAdjacentHTML('beforeend',`<div class="node-info-backdrop"><section class="node-info-dialog" role="dialog" aria-modal="true" aria-label="RPT information"><button class="detail-close node-info-close" aria-label="Close RPT information"><span aria-hidden="true">×</span><b>Close</b></button><div class="eyebrow">RPT INFO · ${escapeHtml(sourceLabel(activeApiSource))}</div><h2>${escapeHtml(node.name||item.name||'Tracked device')}</h2><p class="node-info-key">${escapeHtml(item.key)}</p>${body}</section></div>`);
  document.querySelector('.node-info-close')?.addEventListener('click',closeNodeInfo);
  document.querySelector('.node-info-backdrop')?.addEventListener('click',event=>{if(event.target===event.currentTarget)closeNodeInfo();});
}
async function openNodeInfo(item) {
  const cached=nodeInfoCache.get(item.key);
  if(cached&&Date.now()-cached.savedAt<3600000){showNodeInfo(item,cached.data);return;}
  showNodeInfo(item,null,true);
  try {
    const response=await fetch(apiProxyUrl('neighbours',{id:item.key}),{cache:'no-store'});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||`API returned HTTP ${response.status}`);
    nodeInfoCache.set(item.key,{savedAt:Date.now(),data});showNodeInfo(item,data);
  } catch(cause) {showNodeInfo(item,null,false,cause.message||'Could not load RPT information');}
}
function updateActiveApiLabel() {
  const label=document.getElementById('active-api-source');
  if(label)label.textContent=sourceLabel(activeApiSource);
}
function renderLive() {
  updateActiveApiLabel();
  const status = document.querySelector('.connection-pill span:last-child');
  if (status) status.textContent = liveState.loading ? 'UPDATING' : liveState.error ? 'OFFLINE' : liveState.lastSuccess ? 'LIVE' : 'CONNECTING';
  const dot = document.querySelector('.connection-pill .status-dot');
  if (dot) dot.classList.toggle('offline', !!liveState.error);
  const rows = liveState.packets.map(packet => {
    const decoded = parseDecoded(packet), path = packetPath(packet), relations=enhancedMatches(packet), matches=relations, accent=packetAccent(packet,relations);
    const preview = packetSummary(packet);
    return `<button class="packet-row ${accent}" data-packet-id="${escapeHtml(packet.id)}" type="button">
      <span class="packet-time"><b>${packetTime(packet)}</b><small class="packet-age">${relativeAge(packet)}</small></span>
      <span class="packet-type type-${Number(packet.payload_type)}">${escapeHtml(packetType(packet))}<small>${escapeHtml((packet.direction || 'rx').toUpperCase())}</small></span>
      <span class="packet-copy"><strong>${liveIdentityMarkup(packet)}</strong>${packetPath(packet).some(hop=>String(hop).length===2&&/^[a-f\d]{2}$/i.test(String(hop)))?'<small class="one-byte-marker">1 byte</small>':''}<span>${renderTrackedText(preview)}</span><small>${escapeHtml(packet.observer_iata || 'Observer')} · ${Number(packet.observation_count || 1)} observation${Number(packet.observation_count || 1) === 1 ? '' : 's'}</small>${missingGpsHashes(packet).map(hash=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hash)}</b>`).join('')}${matches.length?`<span class="key-match-list">${matches.map(match=>`<b class="${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} · ${escapeHtml(match.name || keyName(match.key))}</b>${match.relation===trackedRelations.reply&&replyHasNoRoute(packet,match.key)?'<b class="no-route">NO ROUTE</b>':''}`).join('')}</span>`:''}</span>
      <span class="packet-route">${escapeHtml(pathSummary(packet))}<small>${packet.rssi == null ? '' : `${escapeHtml(packet.rssi)} dBm`}</small></span>
    </button>`;
  }).join('');
  const last = liveState.lastSuccess ? new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(liveState.lastSuccess) : '—';
  screen.innerHTML = `<section class="live-screen">
    <div class="live-heading"><div><div class="eyebrow">MESHCORE NETWORK</div><h1>Live packets</h1><p>Packets observed across the public MeshCore feed.</p></div></div>
    <div class="live-meta"><span class="live-count">${liveState.packets.length} / 250 packets</span><span id="last-updated">Updated ${last}</span></div>
    ${liveState.error ? `<div class="feed-error"><strong>Feed temporarily unavailable</strong><span>${escapeHtml(liveState.error)}</span></div>` : ''}
    <div class="packet-list">${rows || `<div class="empty-feed">${liveState.loading?'Connecting to the live feed…':'No packets received yet.'}</div>`}</div>
  </section>${liveState.selected ? renderDetail(liveState.selected) : ''}`;
  screen.querySelectorAll('.packet-row').forEach(row => row.addEventListener('click', () => {
    liveState.selected = liveState.packets.find(item => String(item.id) === row.dataset.packetId) || null; liveState.details=null; liveState.detailsError=''; liveState.showAllRoutes=false; loadPacketDetails(liveState.selected); renderLive();
  }));
  screen.querySelector('.detail-close')?.addEventListener('click', closeDetail);
  screen.querySelector('.detail-close-secondary')?.addEventListener('click', closeDetail);
  screen.querySelector('.route-toggle')?.addEventListener('click',()=>{liveState.showAllRoutes=!liveState.showAllRoutes;renderLive();});
  screen.querySelector('.packet-detail-backdrop')?.addEventListener('click', event => { if(event.target === event.currentTarget) closeDetail(); });
  screen.querySelector('.copy-packet-hash')?.addEventListener('click', event => copyValue(liveState.selected?.hash,event.currentTarget));
  screen.querySelector('.copy-source-key')?.addEventListener('click', event => {const decoded=parseDecoded(liveState.details?.packet || liveState.selected || {});copyValue(decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey,event.currentTarget);});
}
async function copyValue(value,button) { if(!value)return; try{await navigator.clipboard.writeText(value);const old=button.textContent;button.textContent='Copied';setTimeout(()=>{if(button.isConnected)button.textContent=old;},1200);}catch{button.textContent='Copy unavailable';} }
function closeDetail() { liveState.selected=null; liveState.details=null; liveState.detailsLoading=false; liveState.showAllRoutes=false; renderScreen(currentScreen()); }
async function loadPacketDetails(packet, rerender=renderLive) {
  if(!packet) return;
  liveState.detailsLoading=true; liveState.detailsError=''; rerender();
  try { const cached=observationMatchCache.get(String(packet.id)); if(cached?.data?.loadSucceeded) liveState.details=cached.data; else { const response=await fetch(apiProxyUrl('packet',{id:String(packet.id)}),{cache:'no-store'}); if(!response.ok)throw new Error(`HTTP ${response.status}`); liveState.details=await response.json(); } }
  catch(error) { liveState.detailsError=error.message||'Could not load packet observations'; }
  finally { liveState.detailsLoading=false; rerender(); }
}
function renderDetail(packet) {
  const source = liveState.details?.packet || packet;
  const decoded = parseDecoded(source), path = packetPath(source), matches = matchesForPacket(source);
  const fields = [
    ['Sender', decoded.sender || decoded.name || 'Unknown sender'], ['Sender hash', decoded.srcHash || (decoded.pubKey?String(decoded.pubKey).slice(0,4).toUpperCase():null)], ['Payload type', decoded.type || packetType(packet)], ['Channel', decoded.channel],
    ['Observer', packet.observer_name], ['Observer region', packet.observer_iata], ['Observer key', packet.observer_id],
    ['Direction', (packet.direction || 'rx').toUpperCase()], ['Packet time', new Date(packet.timestamp || packet.first_seen).toLocaleString('pl-PL',{timeZone:'Europe/Warsaw'})],
    ['Path', path.length ? path.join('  ›  ') : 'Direct / no path'], ['RSSI', packet.rssi == null ? null : `${packet.rssi} dBm`], ['SNR', packet.snr == null ? null : `${packet.snr} dB`],
    ['Observations', liveState.details?.observation_count ?? packet.observation_count], ['Payload size', packet.raw_hex ? `${Math.floor(packet.raw_hex.length/2)} bytes` : null],
    ['Position', decoded.lat != null && decoded.lon != null ? `${decoded.lat}, ${decoded.lon}` : null], ['Public key', decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey], ['Signature valid', decoded.signatureValid == null ? null : String(decoded.signatureValid)]
  ].filter(([,value]) => value != null && value !== '');
  const decodedFields = Object.entries(decoded).filter(([key])=>!['text','name','sender','type','channel','lat','lon','pubKey','signature','signatureValid'].includes(key));
  const observations = Array.isArray(liveState.details?.observations) ? liveState.details.observations : [];
  const routeGroups = new Map();
  observations.forEach(observation=>{let route=[];try{route=JSON.parse(observation.path_json||'[]')}catch{};const resolved=Array.isArray(observation.resolved_path)?observation.resolved_path:[];const key=route.join('/');if(!routeGroups.has(key))routeGroups.set(key,{path:route,resolved,observers:[]});routeGroups.get(key).observers.push(observation);});
  const allRoutes=[...routeGroups.values()].sort((a,b)=>a.path.length-b.path.length);
  const excludedOneByteRoutes=allRoutes.filter(route=>route.path.some(hop=>String(hop).length<4)).length;
  const eligibleRoutes=allRoutes.filter(route=>route.path.every(reliableHash));
  const routeRelations=new Map(eligibleRoutes.map(route=>[route,relationMatches({...source,path_json:JSON.stringify(route.path),resolved_path:route.resolved,observer_id:route.observers[0]?.observer_id})]));
  const trackedRoutes=eligibleRoutes.filter(route=>(routeRelations.get(route)||[]).length>0);
  const showAllRoutes=!!liveState.showAllRoutes;
  const displayedRoutes=!showAllRoutes&&trackedRoutes.length?trackedRoutes:eligibleRoutes;
  const hashWidth=eligibleRoutes.length ? new Set(eligibleRoutes.flatMap(route=>route.path.map(hop=>String(hop).length/2))).size===1 ? String(eligibleRoutes[0].path[0]||'').length/2 : null : null;
  const routeMarkup = displayedRoutes.map(route=>{
    const routeMatches=routeRelations.get(route)||[];
    const chain=route.path.map((hop,index)=>{
      const item=uniqueKeyForHash(hop), relation=index===route.path.length-1?trackedRelations.end:trackedRelations.route;
      const isMatched=!!item&&routeMatches.some(match=>match.key===item.key&&match.relation===relation);
      return `<span class="${isMatched?'route-hop-tracked':''}">${escapeHtml(hop)}</span>${item&&isMatched?` <b class="matched-hop">${escapeHtml(item.name||keyName(item.key))}</b>`:''}`;
    }).join(' <span class="route-arrow">›</span> ');
    const noGps=route.path.filter((hop,index)=>confirmedMissingGps(hop,route.resolved[index]||'')).map(hop=>String(hop).slice(0,4).toUpperCase());
    const observerMarkup=route.observers.map(item=>{
      const matches=relationMatches({...source,path_json:JSON.stringify(route.path),resolved_path:route.resolved,observer_id:item.observer_id});
      const reported=matches.some(match=>match.relation===trackedRelations.observer);
      const observerMatch=matches.find(match=>match.relation===trackedRelations.observer);
      const observerKey=reported ? ` · ${escapeHtml(String(observerMatch?.key||'').slice(0,4).toUpperCase())}` : '';
      const rssi=item.rssi==null?'RSSI —':`${escapeHtml(item.rssi)} dBm`;
      const snr=item.snr==null?'SNR —':`${escapeHtml(item.snr)} dB`;
      const relationMarkup=matches.map(match=>`<b class="relation-chip ${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} · ${escapeHtml(match.name||keyName(match.key))}</b>`).join('');
      return `<div class="route-observer ${reported?'tracked-observer':''}">Observed by ${escapeHtml(item.observer_name||'Unknown observer')}${observerKey} · ${escapeHtml(item.observer_iata||'—')} · ${rssi} · ${snr}${relationMarkup}</div>`;
    }).join('');
    const gpsMarkup=noGps.map(hash=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hash)}</b>`).join('');
    return `<div class="observed-route">${gpsMarkup}<code>${chain||'Direct / no route'}</code><small>${Math.max(0,route.path.length-1)} hops · ${route.observers.length} observation${route.observers.length===1?'':'s'}</small>${observerMarkup}</div>`;
  }).join('');
  const sourceKey=decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey;
  return `<div class="packet-detail-backdrop"><section class="packet-detail" role="dialog" aria-modal="true" aria-label="Packet details"><button class="detail-close" aria-label="Close packet details"><span aria-hidden="true">×</span><b>Close</b></button><div class="eyebrow">PACKET DETAILS · ${escapeHtml(packetType(packet))} · ${(packet.direction || 'rx').toUpperCase()}</div><h2>${escapeHtml(decoded.sender || decoded.name || 'Mesh packet')}</h2><p class="detail-message">${escapeHtml(packetSummary(source))}</p>${matches.length?`<div class="detail-key-matches">${matches.map(match=>`<b class="relation-chip ${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} · ${escapeHtml(match.name||keyName(match.key))}</b>`).join('')}</div>`:''}<dl>${fields.map(([key,value])=>`<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>${liveState.detailsLoading?'<p class="details-loading">Loading all observations and routes…</p>':''}${liveState.detailsError?`<p class="details-error">Could not load additional routes: ${escapeHtml(liveState.detailsError)}</p>`:''}${excludedOneByteRoutes?`<p class="route-excluded-note">1-byte routes excluded: ${excludedOneByteRoutes}</p>`:''}${eligibleRoutes.length?`<section class="observed-routes"><h3>${trackedRoutes.length&&!showAllRoutes?'TRACKED ROUTES':'OBSERVED ROUTES'} · ${displayedRoutes.length} ROUTES / ${observations.length} OBSERVATIONS</h3>${hashWidth?`<p class="route-hash-width">Path hashes: ${hashWidth} ${hashWidth===1?'byte':'bytes'} per hop</p>`:''}${routeMarkup}${trackedRoutes.length<eligibleRoutes.length?`<button class="route-toggle" type="button">${showAllRoutes?'Show tracked routes':`Show all ${eligibleRoutes.length} routes`}</button>`:''}</section>`:''}${decodedFields.length?`<div class="decoded-block"><span>DECODED FIELDS</span>${decodedFields.map(([key,value])=>`<div><b>${escapeHtml(key)}</b><code>${escapeHtml(typeof value==='object'?JSON.stringify(value):value)}</code></div>`).join('')}</div>`:''}${packet.raw_hex?`<div class="raw-block"><span>RAW HEX</span><code>${escapeHtml(packet.raw_hex)}</code></div>`:''}<div class="detail-actions"><button class="copy-packet-hash" type="button">Copy packet hash</button><button class="detail-close-secondary" type="button">Close packet</button>${sourceKey?'<button class="copy-source-key" type="button">Copy source key</button>':''}</div></section></div>`;
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
async function enrichPacketObservations(packets, source) {
  if(!trackedKeys.length) return;
  const savedDirectory=gpsDirectoryCache.get(source);
  if(!savedDirectory || Date.now()-savedDirectory.loadedAt>=GPS_DIRECTORY_CACHE_MS) {
    try {
      const response=await fetch(apiProxyUrl('directory',{},source),{cache:'no-store'});
      const data=await response.json();
      if(response.ok&&Array.isArray(data.nodes)) gpsDirectoryCache.set(source,{loadedAt:Date.now(),nodes:data.nodes});
    } catch { /* A missing directory simply suppresses the NO GPS marker. */ }
  }
  const activeIds=new Set(packets.map(packet=>String(packet.id)));
  [...observationMatchCache.keys()].forEach(id=>{if(!activeIds.has(id))observationMatchCache.delete(id);});
  const now=Date.now();
  const candidates=packets.filter(packet=>Number(packet.observation_count||1)>1 || matchesForPacket(packet).length>0).filter(packet=>{
    const cached=observationMatchCache.get(String(packet.id));
    return !cached || cached.observationCount!==Number(packet.observation_count||1) || now-cached.checkedAt>=OBSERVATION_CACHE_MS;
  });
  let next=0;
  async function worker(){
    while(next<candidates.length){
      const packet=candidates[next++];
      try {
        const response=await fetch(apiProxyUrl('packet',{id:String(packet.id)},source),{cache:'no-store'});
        if(!response.ok)continue;
        const raw=await response.json();
        observationMatchCache.set(String(packet.id),{observationCount:Number(packet.observation_count||1),checkedAt:Date.now(),data:{...raw,loadSucceeded:true}});
      } catch { /* The public feed remains usable if one details request fails. */ }
    }
  }
  await Promise.all(Array.from({length:Math.min(MAX_OBSERVATION_REQUESTS,candidates.length)},worker));
  // A route discovered only in the observation details counts for a saved key
  // exactly once, just like a direct source/observer match.
  recordTrackedPacketCounters(packets);
  updateMyLog(packets);
  if(source===activeApiSource && currentScreen()==='Live' && !liveState.selected) renderLive();
}
async function loadPackets(manual = false) {
  if (liveState.loading || document.hidden) return;
  const previousIds=liveState.packets.map(item=>item.id).join(','), previousError=liveState.error;
  liveState.loading = true; if(manual) renderLive();
  try {
    let lastError=null, result=null;
    for(const source of apiSources){
      try {
        const response=await fetch(apiProxyUrl('packets',{limit:'250'},source),{cache:'no-store'});
        if(!response.ok)throw new Error(`HTTP ${response.status}`);
        const data=await response.json();
        if(!Array.isArray(data.packets))throw new Error('Invalid packet-feed response');
        result={source,packets:data.packets};break;
      } catch(error) { lastError=error; }
    }
    if(!result)throw new Error(`All configured APIs are unavailable${lastError?.message?`: ${lastError.message}`:''}`);
    activeApiSource=result.source;
    updateActiveApiLabel();
    liveState.packets = result.packets.sort((a,b)=>new Date(b.timestamp||b.first_seen)-new Date(a.timestamp||a.first_seen));
    recordTrackedPacketCounters(liveState.packets);
    updateMyLog(liveState.packets);
    liveState.error = ''; liveState.lastSuccess = Date.now();
  } catch (error) { liveState.error = error.message || 'Connection failed'; }
  finally {
    liveState.loading = false;
    nextRefreshAt = Date.now() + refreshIntervalMs;
    const changed=previousIds!==liveState.packets.map(item=>item.id).join(',') || previousError!==liveState.error;
    if(currentScreen()==='Live'&&(manual || (!liveState.selected && changed))) renderLive();
    else if(currentScreen()==='Live') updateLiveIndicators();
    updateRefreshCountdown();
  }
  if(!liveState.error) enrichPacketObservations(liveState.packets,activeApiSource);
}
function updateRefreshCountdown() {
  const countdown = document.getElementById('refresh-countdown');
  if (countdown) countdown.textContent = `${Math.max(0, nextRefreshAt - Date.now())} ms`;
  const button = document.getElementById('refresh-live-top');
  if (button) {
    button.disabled = liveState.loading;
    button.setAttribute('aria-busy', String(liveState.loading));
    button.title = liveState.loading ? 'Refreshing…' : 'Refresh packets now';
  }
}
function updateLiveIndicators() {
  updateActiveApiLabel();
  const status=document.querySelector('.connection-pill span:last-child'), dot=document.querySelector('.connection-pill .status-dot');
  if(status)status.textContent=liveState.error?'OFFLINE':liveState.lastSuccess?'LIVE':'CONNECTING';
  if(dot)dot.classList.toggle('offline',!!liveState.error);
  const updated=document.getElementById('last-updated');
  if(updated)updated.textContent=`Updated ${new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(liveState.lastSuccess)}`;
  document.querySelectorAll('.packet-row').forEach(row=>{const packet=liveState.packets.find(item=>String(item.id)===row.dataset.packetId);const age=row.querySelector('.packet-age');if(packet&&age)age.textContent=relativeAge(packet);});
}
function renderSettings() {
  screen.innerHTML = `<section class="settings-screen"><div class="eyebrow">PERSONALIZE M²</div><h1>Settings</h1><section class="api-settings"><h2>Packet APIs</h2><p class="settings-intro">The app tries these APIs in order. If the first one is unavailable, it switches automatically to the next working source.</p><div class="api-source-list">${apiSources.map((source,index)=>`<div class="api-source-row"><span class="api-order">${index+1}</span><code>${escapeHtml(source)}</code>${source===activeApiSource?'<b class="api-active-badge">ACTIVE</b>':''}<button type="button" data-primary-api="${index}" ${index===0?'disabled':''}>Make primary</button>${apiSources.length>1?`<button type="button" data-remove-api="${index}" aria-label="Remove API ${escapeHtml(source)}">Remove</button>`:''}</div>`).join('')}</div><div class="api-add-form"><label for="api-source-input">Add API base URL</label><div><input id="api-source-input" type="url" autocomplete="url" placeholder="https://api.example.org"><button id="add-api-source" type="button">Add API</button></div><p id="api-source-error" class="form-error" role="status" aria-live="polite"></p></div></section><section class="refresh-settings"><h2>Live refresh interval</h2><p class="settings-intro">Choose how often the packet feed is checked. The countdown next to LIVE follows this interval.</p><label for="refresh-interval">Refresh every</label><select id="refresh-interval">${REFRESH_OPTIONS.map(value=>`<option value="${value}" ${value===refreshIntervalMs?'selected':''}>${formatRefreshInterval(value)}</option>`).join('')}</select></section><section class="tracked-settings"><h2>Tracked keys</h2><p class="settings-intro">Add a full public key to recognize it in packet sources, observers and recorded routes.</p><div class="key-form"><label>Public key · 64 hex characters<input id="tracked-key" autocomplete="off" spellcheck="false" placeholder="Paste the full public key" maxlength="64"></label><button class="add-key-button" id="add-tracked-key" type="button">Add key</button><div id="key-form-error" class="form-error" role="status" aria-live="polite"></div></div><div class="key-storage-note"><span>SESSION ONLY</span> Keys and names are kept only for this browser session. Packet counts below use the loaded feed (${liveState.packets.length} of 250 packets).</div><div class="tracked-key-list"><div class="keys-heading"><strong>Saved keys</strong><span>${trackedKeys.length}</span></div>${trackedKeys.length?trackedKeys.map((item,index)=>`<div class="tracked-key-row"><div><strong>${escapeHtml(item.name||'Name unavailable')}</strong><code>${escapeHtml(item.key)}</code><small class="tracked-packet-count">${packetCountForTrackedKey(item.key)} matching packets in loaded feed</small></div><button type="button" data-remove-key="${index}" aria-label="Remove ${escapeHtml(item.name||'key')}">Remove</button></div>`).join(''):'<div class="empty-keys">No tracked keys yet.</div>'}</div></section></section>`;
  screen.querySelector('.key-storage-note').lastChild.textContent=' Keys, start dates and packet counters are kept only for this browser session.';
  screen.querySelectorAll('.tracked-packet-count').forEach((element,index)=>{
    const item=trackedKeys[index];
    element.textContent=`START ${formatCounterStart(item.counterStartedAt)} · PACKETS ${Number(item.packetCount||0).toLocaleString('en-US')}`;
  });
  screen.querySelectorAll('.tracked-key-row>div').forEach((element,index)=>{
    element.tabIndex=0;element.setAttribute('role','button');element.setAttribute('aria-label',`Open RPT information for ${trackedKeys[index].name||trackedKeys[index].key}`);
    element.addEventListener('click',()=>openNodeInfo(trackedKeys[index]));
    element.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();openNodeInfo(trackedKeys[index]);}});
  });
  document.getElementById('refresh-interval').addEventListener('change',event=>{refreshIntervalMs=Number(event.target.value);sessionStorage.setItem(REFRESH_STORAGE,String(refreshIntervalMs));nextRefreshAt=Date.now()+refreshIntervalMs;updateRefreshCountdown();});
  document.getElementById('add-api-source').addEventListener('click',()=>{const input=document.getElementById('api-source-input'),error=document.getElementById('api-source-error'),source=normalizeApiSource(input.value);if(!source){error.textContent='Enter a valid HTTPS API base URL.';return;}if(apiSources.includes(source)){error.textContent='This API is already in the list.';return;}apiSources.push(source);saveApiSources();renderSettings();loadPackets(true);});
  screen.querySelectorAll('[data-primary-api]').forEach(button=>button.addEventListener('click',()=>{const index=Number(button.dataset.primaryApi);apiSources=[apiSources[index],...apiSources.filter((_,i)=>i!==index)];saveApiSources();activeApiSource=apiSources[0];updateActiveApiLabel();renderSettings();loadPackets(true);}));
  screen.querySelectorAll('[data-remove-api]').forEach(button=>button.addEventListener('click',()=>{apiSources.splice(Number(button.dataset.removeApi),1);saveApiSources();if(!apiSources.includes(activeApiSource)){activeApiSource=apiSources[0];updateActiveApiLabel();}renderSettings();loadPackets(true);}));
  const keyInput=document.getElementById('tracked-key'), error=document.getElementById('key-form-error'), addButton=document.getElementById('add-tracked-key');
  addButton.addEventListener('click',async()=>{
    const key=keyInput.value.trim().replace(/\s+/g,'').toUpperCase();
    if(!/^[A-F0-9]{64}$/.test(key)){error.textContent='Enter a complete 64-character hexadecimal public key.';return;}
    if(trackedKeys.some(item=>item.key.toLowerCase()===key.toLowerCase())){error.textContent='This public key is already saved.';return;}
    addButton.disabled=true;addButton.textContent='Importing name…';error.textContent='Looking up this key in the MeshCore node directory…';
    try {
      const response=await fetch(apiProxyUrl('node',{id:key}),{cache:'no-store'});
      const result=await response.json();
      if(!response.ok)throw new Error(response.status===404?'No exact public-key match was found in the MeshCore API. Check the key and try again.':(result.error||`API returned HTTP ${response.status}`));
      if(String(result.key||'').toLowerCase()!==key.toLowerCase()||!String(result.name||'').trim())throw new Error('The API did not return a name for this exact public key.');
      trackedKeys.push({key,name:String(result.name).trim(),counterStartedAt:Date.now(),packetCount:0,seenPacketIds:[]});saveTrackedKeys();renderSettings();
    } catch(cause) { error.textContent=`Name import failed: ${cause.message||'MeshCore API unavailable'}`;addButton.disabled=false;addButton.textContent='Add key'; }
  });
  keyInput.addEventListener('input',()=>{error.textContent='';});
  screen.querySelectorAll('[data-remove-key]').forEach(button=>button.addEventListener('click',()=>{trackedKeys.splice(Number(button.dataset.removeKey),1);saveTrackedKeys();renderSettings();}));
}
function renderMyLog() {
  const rows=myLogPackets.map(packet=>`<button class="packet-row packet-own" data-my-log-id="${escapeHtml(packet.id)}" type="button"><span class="packet-time"><b>${packetTime(packet)}</b><small class="packet-age">${relativeAge(packet)}</small></span><span class="packet-type type-${Number(packet.payload_type)}">${escapeHtml(packetType(packet))}<small>${escapeHtml((packet.direction||'rx').toUpperCase())}</small></span><span class="packet-copy"><strong>${liveIdentityMarkup(packet)}</strong><span>${renderTrackedText(packetSummary(packet))}</span><small>${escapeHtml(packet.observer_iata||'Observer')} · ${Number(packet.observation_count||1)} observation${Number(packet.observation_count||1)===1?'':'s'}</small></span><span class="packet-route">${escapeHtml(pathSummary(packet))}<small>${packet.rssi==null?'':`${escapeHtml(packet.rssi)} dBm`}</small></span></button>`).join('');
  screen.innerHTML=`<section class="live-screen my-log-screen"><div class="live-heading"><div><div class="eyebrow">SAVED DEVICE ACTIVITY</div><h1>My devices log</h1><p>Newest first · ${myLogPackets.length} / 250</p></div><div class="my-log-actions"><button id="export-my-log" type="button" ${myLogPackets.length?'':'disabled'}>Export</button><button id="clear-my-log" type="button" ${myLogPackets.length?'':'disabled'}>Clear</button></div></div><div class="packet-list">${rows||'<div class="empty-feed">No activity from saved device keys.</div>'}</div></section>${liveState.selected?renderDetail(liveState.selected):''}`;
  screen.querySelectorAll('[data-my-log-id]').forEach(row=>row.addEventListener('click',()=>{liveState.selected=myLogPackets.find(packet=>String(packet.id)===row.dataset.myLogId)||null;liveState.details=null;liveState.detailsError='';liveState.showAllRoutes=false;loadPacketDetails(liveState.selected,renderMyLog);}));
  screen.querySelector('.detail-close')?.addEventListener('click',closeDetail);
  screen.querySelector('.detail-close-secondary')?.addEventListener('click',closeDetail);
  screen.querySelector('.route-toggle')?.addEventListener('click',()=>{liveState.showAllRoutes=!liveState.showAllRoutes;renderMyLog();});
  screen.querySelector('.packet-detail-backdrop')?.addEventListener('click',event=>{if(event.target===event.currentTarget)closeDetail();});
  screen.querySelector('.copy-packet-hash')?.addEventListener('click',event=>copyValue(liveState.selected?.hash,event.currentTarget));
  screen.querySelector('.copy-source-key')?.addEventListener('click',event=>{const decoded=parseDecoded(liveState.details?.packet||liveState.selected||{});copyValue(decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey,event.currentTarget);});
  document.getElementById('clear-my-log')?.addEventListener('click',()=>{myLogPackets=[];saveMyLogPackets();renderMyLog();});
  document.getElementById('export-my-log')?.addEventListener('click',()=>{const content=myLogPackets.map(packet=>`${packetTime(packet)} · ${packetType(packet)} · ${liveIdentityLabel(packet)}\n${packetSummary(packet)}\nHash: ${packet.hash||'—'}\n`).join('\n');const blob=new Blob([content],{type:'text/plain'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`M2_MY_LOG_${new Date().toISOString().replace(/[:.]/g,'-')}.txt`;link.click();URL.revokeObjectURL(url);});
}
async function renderChannels() {
  const selected=liveState.selectedChannel;
  const channel=selected&&savedChannels.find(item=>item.name===selected);
  if(channel&&!channel.loading&&!channel.messages){
    channel.loading=true; renderChannels();
    try { const response=await fetch(apiProxyUrl('channel',{name:channel.name}),{cache:'no-store'});const data=await response.json();if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);channel.messages=Array.isArray(data.messages)?data.messages:[];channel.error=''; }
    catch(error){channel.error=error.message||'Could not load channel messages';}
    finally {channel.loading=false;saveChannels();renderChannels();}
    return;
  }
  const list=savedChannels.map(item=>`<div class="channel-row" data-channel="${escapeHtml(item.name)}"><button class="channel-open" type="button"><b>${escapeHtml(item.name)}</b><span>${item.loading?'Loading…':item.messages?`${item.messages.length} messages`:'Open messages'}</span></button><button data-remove-channel="${escapeHtml(item.name)}" type="button">Remove</button></div>`).join('');
  const messages=channel?.messages||[];
  screen.innerHTML=`<section class="channels-screen"><div class="eyebrow">SAVED CHANNELS</div><h1>${channel?escapeHtml(channel.name):'Channels'}</h1>${channel?`<button id="back-channels" type="button">← All channels</button><div class="channel-messages">${channel.loading?'<div class="empty-feed">Loading messages…</div>':channel.error?`<div class="feed-error">${escapeHtml(channel.error)}</div>`:messages.map(message=>`<article><b>${escapeHtml(message.sender||'Anonymous')}</b><small>${escapeHtml(message.timestamp||'—')} · ${Number(message.hops||0)} hops</small><p>${renderTrackedText(message.text||'')}</p></article>`).join('')||'<div class="empty-feed">No messages received.</div>'}</div>`:`<div class="channel-add"><input id="channel-name" placeholder="#channel or public" autocomplete="off"><button id="add-channel" type="button">Add channel</button></div><div class="channel-list">${list||'<div class="empty-feed">Add a public channel to begin.</div>'}</div>`}</section>`;
  document.getElementById('back-channels')?.addEventListener('click',()=>{liveState.selectedChannel='';renderChannels();});
  document.getElementById('add-channel')?.addEventListener('click',()=>{const input=document.getElementById('channel-name');const name=input.value.trim();if(!/^(public|#[^\s]{1,127})$/i.test(name)){input.setCustomValidity('Use public or a # channel name.');input.reportValidity();return;}if(!savedChannels.some(item=>item.name.toLowerCase()===name.toLowerCase())){savedChannels.unshift({name,messages:null,error:'',loading:false});saveChannels();}renderChannels();});
  screen.querySelectorAll('.channel-open').forEach(button=>button.addEventListener('click',()=>{liveState.selectedChannel=button.closest('[data-channel]').dataset.channel;renderChannels();}));
  screen.querySelectorAll('[data-remove-channel]').forEach(button=>button.addEventListener('click',event=>{event.stopPropagation();savedChannels=savedChannels.filter(item=>item.name!==button.dataset.removeChannel);saveChannels();renderChannels();}));
}
function renderPlaceholder(name) {
  const descriptions = {'My log':'A focused log of packets related to the public keys you save in Settings.','Channels':'Public and locally decrypted private channels, with the M² channel tools.','Map':'Tracked packet routes, repeaters, distances and the longest-route flight.','Settings':'Saved devices, API selection, refresh behaviour and web-session key controls.','Guide':'Packet types, route colours, map modes and network-data notes.'};
  screen.innerHTML = `<section class="welcome-panel"><div class="eyebrow">${escapeHtml(name.toUpperCase())}</div><h1>${escapeHtml(name)}</h1><p>${escapeHtml(descriptions[name])}</p></section>`;
}
function currentScreen() { return document.querySelector('.nav-item.active')?.dataset.screen || 'Live'; }
function renderScreen(name) { if(name==='Live')renderLive();else if(name==='My log')renderMyLog();else if(name==='Channels')renderChannels();else if(name==='Settings')renderSettings();else if(name==='Guide')renderGuide();else renderPlaceholder(name); }
const allowedScreens=tabButtons.map(button=>button.dataset.screen);
let initialScreen='Live';try{const saved=sessionStorage.getItem(ACTIVE_TAB_STORAGE);if(allowedScreens.includes(saved))initialScreen=saved;}catch{}
tabButtons.forEach(item=>{const active=item.dataset.screen===initialScreen;item.classList.toggle('active',active);if(active)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current');});
renderScreen(initialScreen);
tabButtons.forEach(button => button.addEventListener('click', () => {
  const name = button.dataset.screen;
  tabButtons.forEach(item => { item.classList.toggle('active',item===button); if(item===button)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current'); });
  try { sessionStorage.setItem(ACTIVE_TAB_STORAGE,name); } catch {}
  renderScreen(name);
}));
loadPackets();
document.getElementById('refresh-live-top')?.addEventListener('click', () => loadPackets(true));
setInterval(() => {
  if(document.hidden || document.querySelector('.nav-item.active')?.dataset.screen!=='Live') return;
    if(Date.now() >= nextRefreshAt && !liveState.loading) loadPackets(false);
  updateRefreshCountdown();
}, 50);
setInterval(() => { if(!document.hidden && document.querySelector('.nav-item.active')?.dataset.screen==='Live') document.querySelectorAll('.packet-row').forEach(row=>{const item=liveState.packets.find(packet=>String(packet.id)===row.dataset.packetId);const age=row.querySelector('.packet-age');if(item&&age)age.textContent=relativeAge(item);}); }, 1000);
document.addEventListener('visibilitychange', () => { if(!document.hidden && document.querySelector('.nav-item.active')?.dataset.screen==='Live') loadPackets(); });

// M² intro: a short local signal-flight animation, independent of network status.
if (!window.M2PlayIntro) document.getElementById('intro')?.remove();
else {
const canvas=document.getElementById('signal-canvas'),context=canvas.getContext('2d'),start=performance.now();
const points=Array.from({length:66},(_,i)=>({x:40+fract(Math.sin(i*17.123)*43758.5453)*540,y:80+fract(Math.sin(i*31.91)*12345.678)*1080})),links=[];
points.forEach((point,index)=>points.map((other,target)=>({target,distance:Math.hypot(other.x-point.x,other.y-point.y)})).filter(item=>item.target!==index).sort((a,b)=>a.distance-b.distance).slice(0,2).filter(item=>item.target>index).forEach(item=>links.push([index,item.target])));
const route=[{x:90,y:1050},{x:245,y:870},{x:390,y:700},{x:265,y:475},{x:470,y:290},{x:325,y:125}];
function fract(value){return value-Math.floor(value);} function ease(value){const x=Math.max(0,Math.min(1,value));return x*x*(3-2*x);} function resize(){const dpr=Math.min(devicePixelRatio||1,2);canvas.width=innerWidth*dpr;canvas.height=innerHeight*dpr;}
addEventListener('resize',resize);resize();
function frame(now){const seconds=(now-start)/1000,dpr=canvas.width/innerWidth;context.setTransform(dpr,0,0,dpr,0,0);context.clearRect(0,0,innerWidth,innerHeight);const scale=Math.max(innerWidth/620,innerHeight/1240)*(1.75-.75*ease(seconds/3.8)),panY=innerHeight/2+100*(1-ease(seconds/3.8))*scale,panX=innerWidth/2,project=p=>({x:panX+(p.x-310)*scale,y:panY+(p.y-620)*scale});context.lineWidth=1;context.strokeStyle='#36504355';links.forEach(([a,b])=>{const p=project(points[a]),q=project(points[b]);context.beginPath();context.moveTo(p.x,p.y);context.lineTo(q.x,q.y);context.stroke();});points.forEach(point=>{const p=project(point);context.beginPath();context.fillStyle='#54736166';context.arc(p.x,p.y,2,0,Math.PI*2);context.fill();});const progress=Math.min(seconds/3.6,1)*5;route.slice(0,-1).forEach((point,index)=>{const amount=Math.max(0,Math.min(1,progress-index));if(!amount)return;const end=route[index+1],tip={x:point.x+(end.x-point.x)*amount,y:point.y+(end.y-point.y)*amount},p=project(point),q=project(tip);context.lineCap='round';context.strokeStyle='#68f69b14';context.lineWidth=18;context.beginPath();context.moveTo(p.x,p.y);context.lineTo(q.x,q.y);context.stroke();context.strokeStyle='#68f69b40';context.lineWidth=9;context.beginPath();context.moveTo(p.x,p.y);context.lineTo(q.x,q.y);context.stroke();context.strokeStyle='#68f69b';context.lineWidth=3;context.beginPath();context.moveTo(p.x,p.y);context.lineTo(q.x,q.y);context.stroke();[p,...(amount<1?[q]:[])].forEach(glow);});route.forEach((point,index)=>{if(progress<index)return;const p=project(point);context.beginPath();context.fillStyle='#a0ffbb';context.arc(p.x,p.y,4,0,Math.PI*2);context.fill();});const vignette=context.createRadialGradient(innerWidth/2,innerHeight/2,innerHeight*.1,innerWidth/2,innerHeight/2,innerHeight*.65);vignette.addColorStop(0,'transparent');vignette.addColorStop(1,'#080e0beB');context.fillStyle=vignette;context.fillRect(0,0,innerWidth,innerHeight);if(seconds<5)requestAnimationFrame(frame);else document.getElementById('intro').classList.add('hide');}
function glow(point){const gradient=context.createRadialGradient(point.x,point.y,1,point.x,point.y,32);gradient.addColorStop(0,'#68f69b99');gradient.addColorStop(1,'#68f69b00');context.fillStyle=gradient;context.beginPath();context.arc(point.x,point.y,32,0,Math.PI*2);context.fill();} requestAnimationFrame(frame);
}
