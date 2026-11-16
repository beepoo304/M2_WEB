const tabButtons = [...document.querySelectorAll('.nav-item')];
const screen = document.getElementById('screen');
const liveState = { packets: [], loading: false, error: '', lastSuccess: 0, selected: null, details: null, detailsLoading: false, detailsError: '', selectedChannel: '', showAllRoutes: false };
// Mirrors M²'s observation-match cache: a packet is rechecked only if its
// observation count changed or its cached route analysis is older than 30 s.
const observationMatchCache = new Map();
const OBSERVATION_CACHE_MS = 30_000;
const MAX_OBSERVATION_REQUESTS = 2;
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
  if (Number.isNaN(date.getTime())) return '--:--:--';
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
  if (type === 5) { const channel=String(decoded.channel||'').trim()||'Private channel', text=String(decoded.text||'').trim(); return text ? `${channel} · ${decoded.text}` : `${channel} · Message content unavailable`; }
  if (type === 4) return safeText(decoded.name, 'Node advertisement');
  if (type === 2) return 'Encrypted direct message';
  if (type === 8) return 'Path information';
  if (type === 0) return 'Request';
  if (type === 1) return 'Response';
  if (type === 3) return 'Acknowledgement';
  if (type === 11) return 'Control packet';
  return `${packet.raw_hex ? packet.raw_hex.length / 2 : 0} B`;
}
function packetFlagsMarkup(packet) {
  const decoded = parseDecoded(packet);
  const entries = [];
  const add = (label, value) => {
    if (value == null || value === false || value === '') return;
    const text = typeof value === 'boolean' ? label : `${label}: ${String(value)}`;
    if (!entries.includes(text)) entries.push(text);
  };
  const flags = decoded.flags ?? packet.flags;
  if (Array.isArray(flags)) flags.forEach(flag => add(String(flag).toUpperCase(), true));
  else if (flags && typeof flags === 'object') {
    Object.entries(flags).forEach(([name, value]) => add(name.replace(/([A-Z])/g, ' $1').toUpperCase(), value));
  }
  add('ROUTE TYPE', packet.route_type ?? decoded.route_type ?? decoded.routeType);
  add('PAYLOAD VERSION', packet.payload_version ?? decoded.payload_version ?? decoded.payloadVersion);
  add('DIRECTION', packet.direction);
  if (!entries.length) return '';
  return `<span class="packet-flags">${entries.map(flag => `<b>${escapeHtml(flag)}</b>`).join('')}</span>`;
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
  if(role==='COMPANION'&&name)return `<span class="companion-role">COMPANION</span>: ${escapeHtml(name)}`;
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
  const raw=Array.isArray(packet._parsedPath) ? packet._parsedPath : (()=>{try{const value=JSON.parse(packet.path_json||'[]');return Array.isArray(value)?value:['INVALID']}catch{return['INVALID']}})();
  // M² keeps every API path entry intact. In particular, adjacent 1-byte
  // entries must never be merged: doing so corrupts a trace route.
  return raw.map(hop=>String(hop??'').trim().toUpperCase());
}
function pathSummary(packet) {
  const path = packetPath(packet);
  if (!path.length) return 'direct';
  if (path.some(hop => String(hop).length === 2)) return '1-byte route';
  return `${path.length} hops`;
}
function keyName(key) { return trackedKeys.find(item=>item.key.toLowerCase()===String(key||'').toLowerCase())?.name || `${String(key||'').slice(0,4).toUpperCase()}…`; }
function reliableHash(value) { const text=String(value||'').trim();return text.length>=4&&text.length<=64&&text.length%2===0&&/^[a-f\d]+$/i.test(text); }
function isHexHash(value) { const text=String(value||'').trim();return text.length>=2&&text.length<=64&&text.length%2===0&&/^[a-f\d]+$/i.test(text); }
function uniqueKeyForHash(hash) { if(!isHexHash(hash))return null;const found=trackedKeys.filter(item=>item.key.toLowerCase().startsWith(String(hash).toLowerCase()));return found.length===1?found[0]:null; }
function exactTrackedKey(value) { const text=String(value||'').trim().toLowerCase();return /^[a-f\d]{64}$/i.test(text)?trackedKeys.find(item=>item.key.toLowerCase()===text)||null:null; }
function uniqueNamedKeys(...names) { const normalized=names.map(name=>String(name||'').trim().toLowerCase()).filter(Boolean);const found=trackedKeys.filter(item=>item.name&&normalized.includes(item.name.trim().toLowerCase()));return found.length===1?found:[]; }
function mentionedTrackedKeys(text) { const message=String(text||'').toLowerCase();return trackedKeys.filter(item=>[item.name,item.key.slice(0,4)].some(raw=>{const value=String(raw||'').trim().toLowerCase();if(!value)return false;const escaped=value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return new RegExp(`(?<![\\p{L}\\p{N}_])@(?:\\[${escaped}\\]|${escaped})(?![\\p{L}\\p{N}_])`,'u').test(message);})); }
function relationMatches(packet) {
  const decoded=parseDecoded(packet),path=packetPath(packet),resolved=Array.isArray(packet.resolved_path)?packet.resolved_path:[];
  const out=[],add=(relation,item)=>{if(item&&!out.some(match=>match.relation===relation&&match.key===item.key))out.push({relation,key:item.key,name:item.name});};
  
  // M² (CoreScopeRepository.parse) builds every direct relation only when the
  // whole path is trackable: a single 1-byte hop makes the packet ambiguous.
  if(!path.every(reliableHash))return out;
  const source=exactTrackedKey(decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey);
  const sourceHash=uniqueKeyForHash(decoded.srcHash);
  const destination=exactTrackedKey(decoded.destKey)||uniqueKeyForHash(decoded.destHash);
  for(const item of [source,sourceHash,...uniqueNamedKeys(decoded.sender,decoded.name)])add(trackedRelations.source,item);
  add('DESTINATION',destination);
  add(trackedRelations.observer,exactTrackedKey(packet.observer_id));
  mentionedTrackedKeys(decoded.text).forEach(item=>add(trackedRelations.reply,item));
  path.forEach((hop,index)=>{
    const resolvedKey=String(resolved[index]||'').toLowerCase();
    const item=resolvedKey.startsWith(String(hop).toLowerCase())?exactTrackedKey(resolvedKey):uniqueKeyForHash(hop);
    add(index===path.length-1?trackedRelations.end:trackedRelations.route,item);
  });
  if(Number(packet.payload_type)===9&&path.every(hop=>reliableHash(hop))&&path.some(hop=>uniqueKeyForHash(hop)))
    path.forEach(hop=>add(trackedRelations.route,uniqueKeyForHash(hop)));
  return out;
}
function matchesForPacket(packet) { return relationMatches(packet).filter(match=>match.relation!=='DESTINATION'); }
function mergeMatches(...lists) {
  const result=[];
  // flat(2): routeMatches to tablica tablic — jeden poziom nie wystarcza,
  // bo pusta trasa ([]) trafiłaby do wyniku jako „match" bez klucza.
  lists.flat(2).forEach(match=>{
    if(match && !Array.isArray(match) && match.relation !== 'DESTINATION' && !result.some(item=>item.relation===match.relation && item.key.toLowerCase()===match.key.toLowerCase())) result.push(match);
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
// M² ownTraffic: any confirmed relation (DESTINATION included), or a trackable
// path whose sender/node name or @mention names a saved device.
function ownTrafficByName(packet) {
  if(!packetPath(packet).every(reliableHash))return false;
  const decoded=parseDecoded(packet);
  const names=new Set(trackedKeys.map(item=>item.name.trim().toLowerCase()).filter(Boolean));
  return names.has(String(decoded.sender||'').trim().toLowerCase())||names.has(String(decoded.name||'').trim().toLowerCase())||mentionedTrackedKeys(decoded.text).length>0;
}
function packetAccent(packet,matches) {
  const path=packetPath(packet);
  // Match Android LiveLogScreen precedence: ambiguous 1-byte route, then reply, then own traffic.
  if(path.some(hop=>String(hop).length===2&&/^[a-f0-9]{2}$/i.test(String(hop))))return 'packet-one-byte';
  if(matches.some(match=>match.relation===trackedRelations.reply))return 'packet-reply';
  if(matches.length||relationMatches(packet).some(match=>match.relation==='DESTINATION')||ownTrafficByName(packet))return 'packet-own';
  return '';
}
// TrackedKeyRelations.labels(): fixed relation order, keys sorted, "RELATION · XXXX".
const RELATION_LABEL_ORDER=[trackedRelations.source,trackedRelations.end,trackedRelations.reply,trackedRelations.route,trackedRelations.observer];
function relationLabels(matches) {
  const seen=new Set(), out=[];
  RELATION_LABEL_ORDER.forEach(relation=>matches.filter(match=>match.relation===relation).map(match=>match.key.toUpperCase()).sort().forEach(key=>{
    const label=`${relation} · ${key.slice(0,4)}`;
    if(!seen.has(label)){seen.add(label);out.push({relation,key,label});}
  }));
  return out;
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
// Kanały są trwałe (localStorage) jak w M² Android; stary format sesyjny jest migrowany.
function migrateChannel(value) {
  return {
    name:String(value?.name||'').trim(),
    hash:String(value?.hash||''),
    secret:String(value?.secret||''),
    isPrivate:!!value?.isPrivate,
    lastReadAt:Number(value?.lastReadAt)||0,
    clearedAt:Number(value?.clearedAt)||0,
    messages:Array.isArray(value?.messages)?value?.messages.filter(Boolean).slice(0,250):[],
    loading:false, error:''
  };
}
function loadChannels() {
  try {
    const value=JSON.parse(localStorage.getItem(CHANNEL_STORAGE)||'null');
    if(Array.isArray(value)) return value.filter(item=>typeof item?.name==='string').slice(0,50).map(migrateChannel);
  } catch {}
  try {
    const legacy=JSON.parse(sessionStorage.getItem(CHANNEL_STORAGE)||'[]');
    if(Array.isArray(legacy)&&legacy.length){ sessionStorage.removeItem(CHANNEL_STORAGE); return legacy.filter(item=>typeof item?.name==='string').slice(0,50).map(migrateChannel); }
  } catch {}
  return [];
}
function saveChannels() { try { localStorage.setItem(CHANNEL_STORAGE,JSON.stringify(savedChannels.slice(0,50))); } catch {} }

/** Deszyfracja wiadomości prywatnych kanałów z bieżącego strumienia pakietów (payload_type 5). */
async function syncChannelSecrets() {
  let changed = false;
  for (const channel of savedChannels) {
    if (channel.name.startsWith('#') && (!channel.secret || !channel.hash)) {
      const parsed = await M2Channels.parseChannel(channel.name);
      if (parsed) {
        channel.secret = parsed.secret;
        channel.hash = parsed.hash;
        changed = true;
      }
    }
  }
  if (changed) {
    saveChannels();
  }
  await channelsDecryptLive(liveState.packets);
  if (currentScreen() === 'Live') renderLive();
  if (currentScreen() === 'Channels') renderChannels();
}

async function channelsDecryptLive(packets) {
  const keyed=savedChannels.filter(channel=>channel.secret);
  if(!keyed.length)return;
  let changed=false;
  for(const packet of (Array.isArray(packets)?packets:[])) {
    if(Number(packet.payload_type)!==5 && Number(packet.payload_type)!==6)continue;
    const decoded=parseDecoded(packet);
    const channelHashHex=String(decoded.channelHashHex||'');
    const encrypted=String(decoded.encryptedData||''), mac=String(decoded.mac||'');
    if(!channelHashHex||!encrypted||!mac)continue;
    for(const channel of keyed) {
      if(String(channel.hash).toLowerCase()!==channelHashHex.toLowerCase())continue;
      if(!(await M2Channels.validMac(channel.secret,mac,encrypted)))continue;
      const message=await M2Channels.decryptMessage(channel.secret,encrypted);
      if(!message)continue;
      decoded.sender = message.sender;
      decoded.text = message.text;
      decoded.channel = channel.name;
      decoded.decryptionStatus = 'decrypted';
      packet._decoded = decoded;
      const incoming={ id:String(packet.id), sender:message.sender, text:message.text, timestamp:message.timestamp,
        hops:packetPath(packet).length, observers:[packet.observer_name].filter(Boolean),
        repeats:Number(packet.observation_count||1), snr:packet.snr??null, packetHash:packet.hash||'' };
      const merged=M2Channels.mergeMessages(channel.messages,[incoming],channel.clearedAt);
      if(merged.length!==channel.messages.length||merged[0]?.id!==channel.messages[0]?.id){ channel.messages=merged; changed=true; }
    }
  }
  if(changed){ saveChannels(); channelStatsRefresh(); if(currentScreen()==='Channels')renderChannels(); }
}

/** Wiadomości kanału bez sekretu (public / #nazwa) — pobierane z API jak w Androidzie. */
async function channelsLoadRemote(channel) {
  if(channel.isPrivate||channel.loading)return;
  channel.loading=true; if(currentScreen()==='Channels')renderChannels();
  try {
    const response=await fetch(apiProxyUrl('channel',{name:channel.name}),{cache:'no-store'});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    const fresh=(Array.isArray(data.messages)?data.messages:[]).map((message,index)=>({
      id:String(message.packetId||message.id||`${channel.name}-${index}`),
      sender:String(message.sender||'').trim()||'Anonymous', text:String(message.text||''),
      timestamp:String(message.timestamp||''), hops:Number(message.hops||0),
      observers:Array.isArray(message.observers)?message.observers.filter(Boolean):[],
      repeats:Number(message.repeats||1), snr:message.snr??null, packetHash:String(message.packetHash||'')
    }));
    channel.messages=M2Channels.mergeMessages(channel.messages,fresh,channel.clearedAt);
    channel.error='';
  } catch(error) { channel.error=error.message||'Could not load channel messages'; }
  finally { channel.loading=false; saveChannels(); if(currentScreen()==='Channels')renderChannels(); }
}

function trackedNamesLower() { return [...new Set(trackedKeys.map(item=>String(item.name||'').trim().toLowerCase()).filter(Boolean))]; }
function messageIsTracked(message) {
  const names=trackedNamesLower(), sender=String(message.sender||'').trim().toLowerCase();
  if(names.some(name=>sender===name||sender.startsWith(`${name} `)))return true;
  return mentionedTrackedKeys(message.text).length>0;
}
function messageEpochOf(message) { const value=Date.parse(message.timestamp); return Number.isFinite(value)?value:0; }
function warsawDateTime(value) {
  const date=new Date(value);
  return Number.isNaN(date.getTime())?'—':new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(date);
}

// ---------- Statystyki kanałów (port ChannelStatisticsEngine, okno 24 h) ----------
const CHANNEL_STATS_STORAGE='m2-web-channel-stats-v1';
const DAY_MS=24*60*60*1000;
function loadChannelStats() { try { const value=JSON.parse(localStorage.getItem(CHANNEL_STATS_STORAGE)||'[]'); return Array.isArray(value)?value:[]; } catch { return []; } }
function saveChannelStats(events) { try { localStorage.setItem(CHANNEL_STATS_STORAGE,JSON.stringify(events)); } catch {} }
function channelStatsRefresh() {
  const cutoff=Date.now()-DAY_MS;
  const fresh=[];
  savedChannels.forEach(channel=>(channel.messages||[]).forEach(message=>{
    if(messageEpochOf(message)<cutoff)return;
    trackedKeys.forEach(item=>{
      const name=String(item.name||'').trim().toLowerCase();
      if(!name)return;
      const sender=String(message.sender||'').trim();
      const sent=sender.toLowerCase()===name||sender.toLowerCase().startsWith(`${name} `);
      const mention=mentionedTrackedKeys(message.text).some(match=>match.key.toLowerCase()===item.key.toLowerCase());
      if(sent||mention)fresh.push({ id:String(message.id), channel:channel.name, key:item.key, timestamp:message.timestamp, sent, mention });
    });
  }));
  const activeKeys=trackedKeys.map(item=>item.key.toLowerCase());
  const events=[...fresh,...loadChannelStats()]
    .filter(event=>messageEpochOf(event)>=cutoff&&activeKeys.includes(String(event.key||'').toLowerCase()))
    .filter((event,index,all)=>all.findIndex(other=>other.key.toLowerCase()===event.key.toLowerCase()&&other.channel.toLowerCase()===event.channel.toLowerCase()&&other.id===event.id)===index)
    .sort((a,b)=>messageEpochOf(b)-messageEpochOf(a));
  saveChannelStats(events);
  return events;
}
function channelStatsReset(key) { saveChannelStats(loadChannelStats().filter(event=>String(event.key).toLowerCase()!==String(key).toLowerCase())); }

// ---------- Statystyki pakietów aplikacji (port AppPacketStatisticsEngine) ----------
const APP_STATS_STORAGE='m2-web-app-stats-v1';
function loadAppStats() {
  try {
    const value=JSON.parse(localStorage.getItem(APP_STATS_STORAGE)||'null');
    if(value&&Number.isFinite(Number(value.startedAtMs)))return { startedAtMs:Number(value.startedAtMs), packetCount:Math.max(0,Number(value.packetCount)||0), accumulatedRunningMs:Math.max(0,Number(value.accumulatedRunningMs)||0), brokerRunningMs:{}, seen:[] , ...(value.brokerRunningMs?{brokerRunningMs:value.brokerRunningMs}:{}) };
  } catch {}
  return { startedAtMs:Date.now(), packetCount:0, accumulatedRunningMs:0, brokerRunningMs:{}, seen:[] };
}
let appStats=loadAppStats();
let appStatsBroker=sourceLabel(activeApiSource), appStatsBrokerStart=Date.now();
function saveAppStats() { try { localStorage.setItem(APP_STATS_STORAGE,JSON.stringify({ ...appStats, seen:appStats.seen.slice(-2000) })); } catch {} }
function appStatsAccept(packets) {
  let added=0;
  (Array.isArray(packets)?packets:[]).forEach(packet=>{
    const identity=String(packet.hash||'').trim().toLowerCase()||`raw#${Number(packet.payload_type)||0}#${packet.timestamp||''}#${String(packet.raw_hex||'').trim().toLowerCase()}`;
    if(!appStats.seen.includes(identity)){ appStats.seen.push(identity); added++; }
  });
  if(appStats.seen.length>2000)appStats.seen.splice(0,appStats.seen.length-2000);
  if(added){ appStats.packetCount+=added; saveAppStats(); }
}
function appStatsSwitchBroker() {
  const host=sourceLabel(activeApiSource), now=Date.now();
  if(host===appStatsBroker)return;
  appStats.brokerRunningMs[appStatsBroker]=(appStats.brokerRunningMs[appStatsBroker]||0)+(now-appStatsBrokerStart);
  appStatsBroker=host; appStatsBrokerStart=now; saveAppStats();
}
setInterval(()=>{ if(document.hidden||appClosed)return; const now=Date.now(); appStats.accumulatedRunningMs+=30000; appStats.brokerRunningMs[appStatsBroker]=(appStats.brokerRunningMs[appStatsBroker]||0)+(now-appStatsBrokerStart); appStatsBrokerStart=now; saveAppStats(); },30000);
addEventListener('pagehide',()=>{ const now=Date.now(); appStats.brokerRunningMs[appStatsBroker]=(appStats.brokerRunningMs[appStatsBroker]||0)+(now-appStatsBrokerStart); appStatsBrokerStart=now; saveAppStats(); });
function formatRunningTime(milliseconds) {
  const totalMinutes=Math.max(0,Number(milliseconds)||0)/60000, days=Math.floor(totalMinutes/1440), hours=Math.floor(totalMinutes/60)%24, minutes=Math.floor(totalMinutes)%60;
  return `${days>0?`${days} d `:''}${hours} h ${minutes} min`;
}
function appStatsReset() { appStats={ startedAtMs:Date.now(), packetCount:0, accumulatedRunningMs:0, brokerRunningMs:{}, seen:liveState.packets.map(packet=>String(packet.hash||'').trim().toLowerCase()).filter(Boolean) }; appStatsBroker=sourceLabel(activeApiSource); appStatsBrokerStart=Date.now(); saveAppStats(); }
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
  try {
    const saved=JSON.parse(sessionStorage.getItem(API_STORAGE)||'null');
    if(Array.isArray(saved)){
      const clean=saved.map(normalizeApiSource).filter(Boolean);
      if(clean.length){
        if(!clean.includes('https://mc.inside.net.pl')) clean.unshift('https://mc.inside.net.pl');
        return [...new Set(clean)];
      }
    }
  } catch {}
  return ['https://mc.inside.net.pl', 'https://live.meshcorekk.xyz', 'https://analyzer.marwoj.net'];
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
function rptMetricHelp(key) {
  return {
    role:{pl:'Rola tego węzła w sieci MeshCore: repeater przekazuje dalej pakiety, companion to zwykłe urządzenie mobilne, sensor raportuje dane, a room server utrzymuje kanał.',en:'The role of this node in the MeshCore network: repeater relays packets, companion is a regular mobile device, sensor reports data, room server hosts a channel.'},
    lastHeard:{pl:'Czas od ostatniego pakietu wysłanego przez ten węzeł, który był widoczny dla co najmniej jednego listenera.',en:'Time since the last packet sent by this node was seen by at least one listener.'},
    usefulness:{pl:'Punktowy wskaźnik jakości tego węzła, scalający ruch, tłumienie, redundancję i zasięg.',en:'A point score for this node, combining traffic, attenuation, redundancy and coverage.'},
    traffic:{pl:'Każdy słuchacz widzi część sieci; udział w ruchu to procent widzianych pakietów.',en:'Each listener sees part of the network; traffic share is the percentage of packets seen.'},
    bridge:{pl:'Połączenie między różnymi sub-mesh — węzeł z wysokim wynikiem utrzymuje połączenie między obszarami z słabym zasięgiem.',en:'Linking different sub-mesh — a high-scoring node keeps distant areas connected.'},
    coverage:{pl:'Jak dobry jest odbiór dla obszaru geograficznego obsługiwanego przez ten węzeł.',en:'How good the reception is for the geographic area served by this node.'},
    redundancy:{pl:'Węzeł pośredniczący — jeśli inne węzły z wysokim wynikiem zanikną, ten przejmie świadczenie usług w zasięgu.',en:'A middle node — if other high-scoring nodes disappear, this node takes over service in range.'},
    firstSeen:{pl:'Kiedy ten węzeł był widziany po raz pierwszy w API.',en:'When this node was first seen in the API.'},
    totalPackets:{pl:'Każdy słuchacz widzi część sieci; total packets to suma pakietów widzianych przez nasze API.',en:'Each listener sees part of the network; total packets is the sum seen by our API.'},
    packetsToday:{pl:'Każdy słuchacz widzi część sieci; pakiety dziś to suma widzianych dziś pakietów.',en:'Each listener sees part of the network; packets today is the sum seen today.'},
    avgSnr:{pl:'Średnia moc sygnału nadawania przez ten węzeł; niższe dBm to silniejszy sygnał.',en:'The average power used by this node to transmit; lower dBm is stronger.'},
    avgHops:{pl:'Średnia liczba węzłów pośredniczących potrzebna, żeby dostarczyć pakiet do tego węzła.',en:'The average number of middle nodes needed to deliver a packet to this node.'}
  }[key]||null;
}
function renderRptHelp(key) {
  if(!rptMetricHelp(key))return '';
  return `<button type="button" class="metric-help" data-rpt-help="${escapeHtml(key)}" aria-label="About ${escapeHtml(key)}">ⓘ</button>`;
}
function openRptHelp(key) {
  const help=rptMetricHelp(key);
  if(!help)return;
  const language=/^pl/i.test(navigator.language||'')?'pl':'en';
  document.body.insertAdjacentHTML('beforeend',`<div class="dialog-backdrop rpt-help-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="About ${escapeHtml(key)}"><h3>${escapeHtml(key)}</h3><p class="dialog-note">${escapeHtml(help[language])}</p><div class="dialog-actions"><button type="button" class="dialog-cancel" id="rpt-help-close">Close</button></div></section></div>`);
  document.getElementById('rpt-help-close')?.addEventListener('click',()=>{document.querySelector('.rpt-help-backdrop')?.remove();});
  document.querySelector('.rpt-help-backdrop')?.addEventListener('click',event=>{if(event.target===event.currentTarget)event.currentTarget.remove();});
}
function showNodeInfo(item, data, loading=false, error='') {
  closeNodeInfo();
  const node=data?.node||{},stats=data?.stats||{},neighbours=Array.isArray(data?.neighbours)?data.neighbours:[];
  const heardMs=Date.parse(node.last_heard||node.last_seen||'');
  const active=Number.isFinite(heardMs)&&Date.now()-heardMs<3600000;
  const statusText=loading?'…':error?'':active?'ACTIVE':'INACTIVE';
  const body=loading ? '<p class="details-loading">Loading RPT information and recorded neighbours…</p>' : error ? `<p class="details-error">${escapeHtml(error)}</p>` : `<section class="node-info-grid"><div class="${active?'status-active':''}"><span>STATUS${renderRptHelp('role')}</span><b>${statusText}</b></div><div><span>ROLE</span><b>${escapeHtml(node.role||'—')}</b></div><div><span>LAST HEARD${renderRptHelp('lastHeard')}</span><b>${escapeHtml(nodeInfoDate(node.last_heard||node.last_seen))}</b></div><div><span>USEFULNESS${renderRptHelp('usefulness')}</span><b>${escapeHtml(metric(node.usefulness_score))}${node.usefulness_grade?` · ${escapeHtml(node.usefulness_grade)}`:''}</b></div><div><span>TRAFFIC SHARE${renderRptHelp('traffic')}</span><b>${escapeHtml(metric(node.traffic_share_score))}</b></div><div><span>BRIDGE SCORE${renderRptHelp('bridge')}</span><b>${escapeHtml(metric(node.bridge_score))}</b></div><div><span>COVERAGE${renderRptHelp('coverage')}</span><b>${escapeHtml(metric(node.coverage_score))}</b></div><div><span>REDUNDANCY${renderRptHelp('redundancy')}</span><b>${escapeHtml(metric(node.redundancy_score))}</b></div><div><span>FIRST SEEN${renderRptHelp('firstSeen')}</span><b>${escapeHtml(nodeInfoDate(node.first_seen))}</b></div><div><span>TOTAL PACKETS${renderRptHelp('totalPackets')}</span><b>${Number(stats.totalPackets||0).toLocaleString('en-US')}</b></div><div><span>PACKETS TODAY${renderRptHelp('packetsToday')}</span><b>${Number(stats.packetsToday||0).toLocaleString('en-US')}</b></div><div><span>AVG. SNR${renderRptHelp('avgSnr')}</span><b>${stats.avgSnr==null?'—':`${metric(stats.avgSnr,1)} dB`}</b></div><div><span>AVG. HOPS${renderRptHelp('avgHops')}</span><b>${stats.avgHops==null?'—':metric(stats.avgHops,1)}</b></div></section><section class="neighbour-list"><h3>RECORDED NEIGHBOURS · ${neighbours.length}</h3>${neighbours.length?neighbours.map(neighbour=>`<div><code>${escapeHtml(neighbour.hash)}</code><b>${escapeHtml(neighbour.name)}</b><span>${Number(neighbour.count||0)} routes</span></div>`).join(''):'<p>No reliable neighbour route was found.</p>'}</section>`;
  document.body.insertAdjacentHTML('beforeend',`<div class="node-info-backdrop"><section class="node-info-dialog" role="dialog" aria-modal="true" aria-label="RPT information"><button class="detail-close node-info-close" aria-label="Close RPT information"><span aria-hidden="true">×</span><b>Close</b></button><div class="eyebrow">RPT INFO · ${escapeHtml(sourceLabel(activeApiSource))}</div><h2>${escapeHtml(node.name||item.name||'Tracked device')}</h2><p class="node-info-key">${escapeHtml(item.key)}</p>${body}</section></div>`);
  document.querySelector('.node-info-close')?.addEventListener('click',closeNodeInfo);
  document.querySelector('.node-info-backdrop')?.addEventListener('click',event=>{if(event.target===event.currentTarget)closeNodeInfo();});
  document.querySelectorAll('[data-rpt-help]').forEach(button=>button.addEventListener('click',()=>openRptHelp(button.dataset.rptHelp)));
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
// LIVE renders like M²'s keyed LazyColumn: the shell is built once, rows are
// keyed by packet id and only rows whose markup changed are replaced.
const liveDom = { list:null, rows:new Map() };
let liveRenderRevision = 0;
function liveRowMemoKey(packet) {
  const cached=observationMatchCache.get(String(packet.id));
  return `${liveRenderRevision}|${packet.observation_count||1}|${cached?.checkedAt||0}|${gpsDirectoryCache.get(activeApiSource)?.loadedAt||0}|${parseDecoded(packet).text||''}`;
}
function liveRowHtml(packet) {
  const memo=liveRowMemoKey(packet);
  if(packet._rowMemo===memo&&packet._rowHtml)return packet._rowHtml;
  const relations=enhancedMatches(packet), matches=relations, accent=packetAccent(packet,relations);
  const preview=packetSummary(packet);
  const html=`<button class="packet-row ${accent}" data-packet-id="${escapeHtml(packet.id)}" type="button">
      <span class="packet-time"><b>${packetTime(packet)}</b><small class="packet-age"></small></span>
      <span class="packet-type type-${Number(packet.payload_type)}">${escapeHtml(packetType(packet))}<small>${escapeHtml((packet.direction || 'rx').toUpperCase())}</small></span>
      <span class="packet-copy"><strong>${liveIdentityMarkup(packet)}</strong>${packetFlagsMarkup(packet)}${packetPath(packet).some(hop=>String(hop).length===2&&/^[a-f\d]{2}$/i.test(String(hop)))?'<small class="one-byte-marker">1 byte</small>':''}<span>${renderTrackedText(preview)}</span><small>${escapeHtml(packet.observer_iata || 'Observer')} · ${Number(packet.observation_count || 1)} observation${Number(packet.observation_count || 1) === 1 ? '' : 's'}</small>${missingGpsHashes(packet).map(hash=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hash)}</b>`).join('')}${matches.length?`<span class="key-match-list">${relationLabels(matches).map(match=>`<b class="${match.relation===trackedRelations.reply?'reply':''}" title="${escapeHtml(keyName(match.key))}">${escapeHtml(match.label)}</b>${match.relation===trackedRelations.reply&&replyHasNoRoute(packet,match.key)?'<b class="no-route">NO ROUTE</b>':''}`).join('')}</span>`:''}</span>
      <span class="packet-route">${escapeHtml(pathSummary(packet))}<small>${packet.rssi == null ? '' : `${escapeHtml(packet.rssi)} dBm`}</small></span>
    </button>`;
  packet._rowMemo=memo; packet._rowHtml=html;
  return html;
}
function liveRowElement(html) { const template=document.createElement('template'); template.innerHTML=html.trim(); return template.content.firstElementChild; }
function ensureLiveShell() {
  if(liveDom.list?.isConnected)return false;
  screen.innerHTML = `<section class="live-screen">
    <div class="live-heading"><div><div class="eyebrow">MESHCORE NETWORK</div><h1>Live packets</h1><p>Packets observed across the public MeshCore feed.</p></div></div>
    <div class="live-meta"><span class="live-count"></span><span id="last-updated"></span></div>
    <div class="feed-error-host"></div>
    <div class="packet-list"></div>
  </section><div id="live-detail-host"></div>`;
  liveDom.list=screen.querySelector('.packet-list'); liveDom.rows.clear();
  return true;
}
function firstVisibleLiveRow() {
  if(window.scrollY<40)return null;
  for(const row of liveDom.list.children){ const top=row.getBoundingClientRect().top; if(row.getBoundingClientRect().bottom>0)return {id:row.dataset.packetId,top}; }
  return null;
}
function patchLiveList() {
  const list=liveDom.list, packets=liveState.packets;
  if(!packets.length){ liveDom.rows.clear(); list.innerHTML=`<div class="empty-feed">${liveState.loading||!liveState.lastSuccess?'Connecting to the live feed…':'No packets received yet.'}</div>`; return; }
  list.querySelector('.empty-feed')?.remove();
  // When the reader is scrolled into the list, keep the row under their eyes
  // in place instead of letting new packets push it down.
  const anchor=firstVisibleLiveRow();
  const keep=new Set(); let previous=null;
  for(const packet of packets){
    const id=String(packet.id); keep.add(id);
    const html=liveRowHtml(packet);
    let entry=liveDom.rows.get(id);
    if(!entry){ entry={html,el:liveRowElement(html)}; liveDom.rows.set(id,entry); setRowAge(entry.el,packet); }
    else if(entry.html!==html){ const el=liveRowElement(html); if(entry.el.isConnected)entry.el.replaceWith(el); entry.el=el; entry.html=html; setRowAge(el,packet); }
    const expected=previous?previous.nextElementSibling:list.firstElementChild;
    if(expected!==entry.el)list.insertBefore(entry.el,expected);
    previous=entry.el;
  }
  for(const [id,entry] of liveDom.rows) if(!keep.has(id)){ entry.el.remove(); liveDom.rows.delete(id); }
  if(anchor){ const row=liveDom.rows.get(anchor.id)?.el; if(row?.isConnected){ const delta=row.getBoundingClientRect().top-anchor.top; if(Math.abs(delta)>=1)window.scrollBy(0,delta); } }
}
function setRowAge(row,packet) { const age=row.querySelector('.packet-age'); if(age){ const text=relativeAge(packet); if(age.textContent!==text)age.textContent=text; } }
function updateLiveMeta() {
  const count=screen.querySelector('.live-count'); if(count)count.textContent=`${liveState.packets.length} / 250 packets`;
  const host=screen.querySelector('.feed-error-host');
  if(host){ const html=liveState.error?`<div class="feed-error"><strong>Feed temporarily unavailable</strong><span>${escapeHtml(liveState.error)}</span></div>`:''; if(host.dataset.html!==html){host.innerHTML=html;host.dataset.html=html;} }
}
function renderLiveDetail() {
  if(currentScreen()!=='Live')return;
  ensureLiveShell();
  const host=document.getElementById('live-detail-host');
  if(host)host.innerHTML=liveState.selected?renderDetail(liveState.selected):'';
}
// Cheap per-poll update: rows, counters and indicators only.
function refreshLiveList() {
  if(currentScreen()!=='Live')return;
  const fresh=ensureLiveShell();
  patchLiveList(); updateLiveMeta(); updateLiveIndicators();
  if(fresh&&liveState.selected)renderLiveDetail();
}
function renderLive() {
  liveRenderRevision++;
  refreshLiveList();
  renderLiveDetail();
}
function handleLiveClick(event) {
  const target=event.target;
  if(!(target instanceof Element)||currentScreen()!=='Live')return;
  if(!target.closest('.live-screen, #live-detail-host'))return;
  const row=target.closest('.packet-row[data-packet-id]');
  if(row){
    liveState.selected=liveState.packets.find(item=>String(item.id)===row.dataset.packetId)||null;
    liveState.details=null; liveState.detailsError=''; liveState.showAllRoutes=false;
    loadPacketDetails(liveState.selected,renderLiveDetail); return;
  }
  if(target.closest('.detail-close, .detail-close-secondary')){ closeDetail(); return; }
  if(target.closest('.route-toggle')){ liveState.showAllRoutes=!liveState.showAllRoutes; renderLiveDetail(); return; }
  if(target.classList.contains('packet-detail-backdrop')){ closeDetail(); return; }
  const copyHash=target.closest('.copy-packet-hash');
  if(copyHash){ copyValue(liveState.selected?.hash,copyHash); return; }
  const copyKey=target.closest('.copy-source-key');
  if(copyKey&&liveState.selected){ copyValue(detailKey(liveState.selected),copyKey); }
}
screen.addEventListener('click',handleLiveClick);
async function copyValue(value,button) { if(!value)return; try{await navigator.clipboard.writeText(value);const old=button.textContent;button.textContent='Copied';setTimeout(()=>{if(button.isConnected)button.textContent=old;},1200);}catch{button.textContent='Copy unavailable';} }
function closeDetail() { liveState.selected=null; liveState.details=null; liveState.detailsLoading=false; liveState.showAllRoutes=false; if(currentScreen()==='Live')renderLiveDetail(); else renderScreen(currentScreen()); }
async function loadPacketDetails(packet, rerender=renderLiveDetail) {
  if(!packet) return;
  liveState.detailsLoading=true; liveState.detailsError=''; rerender();
  try { const cached=observationMatchCache.get(String(packet.id)); if(cached?.data?.loadSucceeded) liveState.details=cached.data; else { const response=await fetch(apiProxyUrl('packet',{id:String(packet.id)}),{cache:'no-store'}); if(!response.ok)throw new Error(`HTTP ${response.status}`); liveState.details=await response.json(); } }
  catch(error) { liveState.detailsError=error.message||'Could not load packet observations'; }
  finally { liveState.detailsLoading=false; rerender(); }
}
// PacketObservationRepository.parse: one route per observation, invalid paths
// skipped, deduplicated by path + observer, sorted by length then path text.
function detailRoutes(details) {
  const observations=Array.isArray(details?.observations)?details.observations:Array.isArray(details?.packet?.observations)?details.packet.observations:[];
  const seen=new Set(), routes=[];
  observations.forEach(observation=>{
    let parts;
    try { parts=JSON.parse(observation.path_json||''); } catch { return; }
    if(!Array.isArray(parts))return;
    const path=parts.map(hop=>String(hop??'').trim().toUpperCase());
    const observerKey=String(observation.observer_id||'');
    const id=`${path.join(',')}|${observerKey.toLowerCase()}`;
    if(seen.has(id))return;
    seen.add(id);
    routes.push({path,resolved:Array.isArray(observation.resolved_path)?observation.resolved_path.map(value=>String(value??'')):[],observerName:String(observation.observer_name||'').trim()||'Unknown observer',observerKey,rssi:observation.rssi,snr:observation.snr});
  });
  return routes.sort((a,b)=>a.path.length-b.path.length||a.path.join(', ').localeCompare(b.path.join(', ')));
}
// TrackedKeyMatcher.resolvedRoute + observer: relations carried by one route.
function routeRelations(route) {
  const out=[], add=(relation,item)=>{if(item&&!out.some(match=>match.relation===relation&&match.key===item.key))out.push({relation,key:item.key,name:item.name});};
  route.path.forEach((hop,index)=>{
    if(!reliableHash(hop))return;
    const resolved=route.resolved[index]||'';
    const item=resolved?(resolved.toLowerCase().startsWith(hop.toLowerCase())?exactTrackedKey(resolved):null):uniqueKeyForHash(hop);
    add(index===route.path.length-1?trackedRelations.end:trackedRelations.route,item);
  });
  add(trackedRelations.observer,exactTrackedKey(route.observerKey));
  return out;
}
function hashSizeBytes(routes) { const sizes=new Set(routes.flatMap(route=>route.path.map(hop=>hop.length/2)).filter(size=>size>0)); return sizes.size===1?[...sizes][0]:null; }
function detailKey(packet) { const decoded=parseDecoded(packet); return String(decoded.pubKey||'').trim()||String(packet.observer_id||''); }
function relationLabelMarkup(matches) { return relationLabels(matches).map(match=>`<b class="relation-chip ${match.relation===trackedRelations.reply?'reply':''}" title="${escapeHtml(keyName(match.key))}">${escapeHtml(match.label)}</b>`).join(''); }
// Layout and wording of M² PacketDetailsDialog (LiveLogScreen.kt).
function renderDetail(packet) {
  const decoded=parseDecoded(packet), path=packetPath(packet), matches=enhancedMatches(packet);
  const oneByte=path.some(hop=>hop.length===2&&/^[a-f\d]{2}$/i.test(hop));
  const parts=[`<p class="detail-subtitle">${escapeHtml(packetType(packet))} · ${escapeHtml(packetTime(packet))}</p>`];
  if(oneByte)parts.push('<p class="one-byte-marker detail-one-byte">1 byte</p>');
  if(Number(packet.payload_type)===5){
    const sender=String(decoded.sender||'');
    const srcHash=String(decoded.srcHash||'').trim(), pubKey=String(decoded.pubKey||'').trim();
    const senderHash=reliableHash(srcHash)?srcHash:/^[a-f\d]{64}$/i.test(pubKey)?pubKey.slice(0,4):'';
    parts.push(`<p class="detail-channel"><b>Channel: ${escapeHtml(String(decoded.channel||'').trim()||'Private channel')}</b></p>`);
    if(sender.trim())parts.push(`<p>Sender: ${escapeHtml(sender)}<br>Sender hash: ${escapeHtml(senderHash?senderHash.toUpperCase():'unavailable')}</p>`);
    parts.push(`<p class="detail-message-text">${decoded.text?renderTrackedText(decoded.text):'Message content is not available'}</p>`);
  }
  if(matches.length)parts.push(`<div class="detail-key-matches"><b class="detail-label">Tracked key matches</b>${relationLabelMarkup(matches)}</div>`);
  const details=liveState.details;
  const allRoutes=details?detailRoutes(details):[];
  const excluded=allRoutes.filter(route=>route.path.some(hop=>hop.length<4)).length;
  const routes=allRoutes.filter(route=>route.path.every(reliableHash));
  const relationsByRoute=new Map(routes.map(route=>[route,routeRelations(route)]));
  const trackedRoutes=routes.filter(route=>relationsByRoute.get(route).length>0);
  const showAll=!!liveState.showAllRoutes;
  const displayed=!showAll&&trackedRoutes.length?trackedRoutes:routes;
  if(excluded)parts.push(`<p class="route-excluded-note">1-byte routes excluded: ${excluded}</p>`);
  if(!details){
    parts.push(`<p>Route: ${escapeHtml(path.length?path.join(' → '):'Direct / unavailable')}</p>`);
    if(liveState.detailsLoading)parts.push('<p class="details-loading">Loading all observations and routes…</p>');
    if(liveState.detailsError)parts.push(`<p class="details-error">Could not load additional routes: ${escapeHtml(liveState.detailsError)}</p>`);
  } else if(!routes.length) parts.push('<p>No eligible recorded route</p>');
  else {
    const bytes=hashSizeBytes(routes);
    parts.push(`<section class="observed-routes"><h3>${trackedRoutes.length&&!showAll?`Tracked routes (${trackedRoutes.length})`:`Observed routes (${routes.length})`}</h3>${bytes?`<p class="route-hash-width">Path hashes: ${bytes} ${bytes===1?'byte':'bytes'} per hop</p>`:''}${displayed.map(route=>{
      const relations=relationsByRoute.get(route);
      const observerHash=relations.filter(match=>match.relation===trackedRelations.observer).length===1?relations.find(match=>match.relation===trackedRelations.observer).key.slice(0,4).toUpperCase():null;
      const shown=[...route.path];
      if(observerHash){
        const last=shown.at(-1);
        if(last&&last.toUpperCase()===observerHash){}
        else if(last&&last.length===2&&observerHash.startsWith(last.toUpperCase()))shown[shown.length-1]=observerHash;
        else shown.push(observerHash);
      }
      const chain=shown.map((hop,index)=>{
        const resolved=route.resolved[index]||'';
        const confirmed=!!exactTrackedKey(resolved)||!!uniqueKeyForHash(reliableHash(hop)?hop:'');
        const noGps=confirmedMissingGps(hop,resolved);
        return noGps?`<span class="route-hop-nogps">${escapeHtml(hop)}</span>`:confirmed?`<span class="route-hop-tracked">${escapeHtml(hop)}</span>`:escapeHtml(hop);
      }).join(' <span class="route-arrow">→</span> ');
      const noGpsLines=shown.filter(hop=>confirmedMissingGps(hop)).map(hop=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hop)}</b>`).join('');
      const rssi=route.rssi==null?'RSSI —':`${escapeHtml(route.rssi)} dBm`, snr=route.snr==null?'SNR —':`${escapeHtml(route.snr)} dB`;
      return `<div class="observed-route">${noGpsLines}<code>${chain||'—'}</code><small>${Math.max(0,shown.length-1)} hops · ${rssi} · ${snr}</small><div class="route-observer ${observerHash?'tracked-observer':''}">Observed by ${escapeHtml(route.observerName)}${observerHash?` · ${escapeHtml(observerHash)}`:''}</div>${relations.length?`<div class="route-relations">${relationLabelMarkup(relations)}</div>`:''}</div>`;
    }).join('')}${trackedRoutes.length&&trackedRoutes.length<routes.length?`<button class="route-toggle" type="button">${showAll?'Show tracked routes':`Show all ${routes.length} routes`}</button>`:''}</section>`);
  }
  const total=details?.observation_count??details?.packet?.observation_count??packet.observation_count??1;
  parts.push(`<p>Total observations: ${escapeHtml(total)}</p>`);
  if(!details||!routes.length)parts.push(`<p>Signal: ${packet.rssi==null?'—':`${escapeHtml(packet.rssi)} dBm`} · SNR: ${packet.snr==null?'—':`${escapeHtml(packet.snr)} dB`}</p>`);
  const key=detailKey(packet), hasSource=!!String(decoded.pubKey||'').trim();
  parts.push(`<div class="detail-key-block"><b class="detail-label">${hasSource?'Source key':'Observer key'}</b><code>${escapeHtml(key||'Not available')}</code></div>`);
  parts.push(`<p>Reported by: ${escapeHtml(packet.observer_name||'Unknown observer')}</p>`);
  parts.push(`<p class="detail-mono">Hash: ${escapeHtml(packet.hash||'')}</p>`);
  parts.push(`<p class="detail-mono detail-raw">Raw: ${escapeHtml(packet.raw_hex||'')}</p>`);
  return `<div class="packet-detail-backdrop"><section class="packet-detail" role="dialog" aria-modal="true" aria-label="Packet details"><button class="detail-close" aria-label="Close packet details"><span aria-hidden="true">×</span><b>Close</b></button><h2>${escapeHtml(liveIdentityLabel(packet))}</h2>${parts.join('')}<div class="detail-actions"><button class="copy-packet-hash" type="button" ${packet.hash?'':'disabled'}>Copy Hash</button><button class="copy-source-key" type="button" ${key?'':'disabled'}>Copy key</button><button class="detail-close-secondary" type="button">Close</button></div></section></div>`;
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
// M² polling model: sticky active source, failover only after 30 s of failure,
// a failed alternative cools down for 180 s, retries back off 6 s → 30 s and a
// hidden tab keeps polling slowly (30 s) instead of stopping.
const FETCH_TIMEOUT_MS = 15_000;
const FAILOVER_AFTER_MS = 30_000;
const SOURCE_COOLDOWN_MS = 180_000;
const HIDDEN_REFRESH_MS = 30_000;
const UPDATING_GRACE_MS = 6_000;
const sourceFailures = new Map();
let pollFailures = 0, loadingStartedAt = 0, enrichRunning = false;
async function fetchJson(url, timeoutMs=FETCH_TIMEOUT_MS) {
  const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),timeoutMs);
  try {
    const response=await fetch(url,{cache:'no-store',signal:controller.signal});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch(error) { throw error?.name==='AbortError'?new Error('Request timed out'):error; }
  finally { clearTimeout(timer); }
}
function currentRefreshInterval() { return document.hidden ? Math.max(refreshIntervalMs,HIDDEN_REFRESH_MS) : refreshIntervalMs; }
function pollSourceOrder(now=Date.now()) {
  if(!apiSources.includes(activeApiSource))activeApiSource=apiSources[0];
  const failing=sourceFailures.get(activeApiSource);
  if(!failing||now-failing.since<FAILOVER_AFTER_MS)return [activeApiSource];
  return [activeApiSource,...apiSources.filter(source=>source!==activeApiSource&&!((sourceFailures.get(source)?.cooldownUntil||0)>now))];
}
function noteSourceFailure(source, now=Date.now()) {
  const entry=sourceFailures.get(source)||{since:now,cooldownUntil:0};
  if(source!==activeApiSource)entry.cooldownUntil=now+SOURCE_COOLDOWN_MS;
  sourceFailures.set(source,entry);
}
// Stable identity like M²: one entry per id, newest API order preserved, and
// an unchanged packet keeps its object so cached parsing/decryption survive.
function mergeFeedPackets(incoming) {
  const previous=new Map(liveState.packets.map(packet=>[String(packet.id),packet]));
  const seen=new Set(), result=[];
  for(const packet of incoming){
    const id=String(packet?.id??'');
    if(!id||seen.has(id))continue;
    seen.add(id);
    const old=previous.get(id);
    const same=old&&old.observation_count===packet.observation_count&&old.path_json===packet.path_json&&old.decoded_json===packet.decoded_json&&old.raw_hex===packet.raw_hex;
    result.push(same?old:packet);
    if(result.length>=250)break;
  }
  return result;
}
async function enrichPacketObservations(packets, source) {
  if(!trackedKeys.length||enrichRunning) return;
  enrichRunning=true;
  let fetched=0;
  try {
    const savedDirectory=gpsDirectoryCache.get(source);
    if(!savedDirectory || Date.now()-savedDirectory.loadedAt>=GPS_DIRECTORY_CACHE_MS) {
      try {
        const data=await fetchJson(apiProxyUrl('directory',{},source));
        if(Array.isArray(data.nodes)) { gpsDirectoryCache.set(source,{loadedAt:Date.now(),nodes:data.nodes}); fetched++; }
      } catch { /* A missing directory simply suppresses the NO GPS marker. */ }
    }
    const activeIds=new Set(packets.map(packet=>String(packet.id)));
    [...observationMatchCache.keys()].forEach(id=>{if(!activeIds.has(id))observationMatchCache.delete(id);});
    const now=Date.now();
    const candidates=packets.filter(packet=>Number(packet.observation_count||1)>1 || matchesForPacket(packet).length>0).filter(packet=>{
      const cached=observationMatchCache.get(String(packet.id));
      if(!cached)return true;
      if(cached.failedAt)return now-cached.failedAt>=OBSERVATION_CACHE_MS;
      return cached.observationCount!==Number(packet.observation_count||1) || now-cached.checkedAt>=OBSERVATION_CACHE_MS;
    });
    let next=0;
    async function worker(){
      while(next<candidates.length){
        const packet=candidates[next++];
        const previous=observationMatchCache.get(String(packet.id));
        try {
          const raw=await fetchJson(apiProxyUrl('packet',{id:String(packet.id)},source));
          observationMatchCache.set(String(packet.id),{observationCount:Number(packet.observation_count||1),checkedAt:Date.now(),data:{...raw,loadSucceeded:true}});
          fetched++;
        } catch {
          // Negative cache: keep any earlier good data, but do not retry for 30 s.
          observationMatchCache.set(String(packet.id),previous?.data?{...previous,checkedAt:Date.now()}:{observationCount:Number(packet.observation_count||1),checkedAt:Date.now(),failedAt:Date.now()});
        }
      }
    }
    await Promise.all(Array.from({length:Math.min(MAX_OBSERVATION_REQUESTS,candidates.length)},worker));
  } finally { enrichRunning=false; }
  if(!fetched)return;
  // A route discovered only in the observation details counts for a saved key
  // exactly once, just like a direct source/observer match.
  recordTrackedPacketCounters(packets);
  updateMyLog(packets);
  mapIngest();
  if(source===activeApiSource && currentScreen()==='Live') refreshLiveList();
  if(source===activeApiSource && currentScreen()==='Map' && typeof updateMapView === 'function') updateMapView();
}
async function loadPackets(manual = false) {
  if (liveState.loading || appClosed) return;
  liveState.loading = true; loadingStartedAt = Date.now();
  if(manual) updateRefreshCountdown();
  try {
    let lastError=null, result=null;
    for(const source of pollSourceOrder()){
      const startedAt=Date.now();
      try {
        const data=await fetchJson(apiProxyUrl('packets',{limit:'250',_:String(Date.now())},source));
        if(!Array.isArray(data.packets))throw new Error('Invalid packet-feed response');
        recordApiHealth(source,true,Date.now()-startedAt);
        sourceFailures.delete(source);
        result={source,packets:data.packets};break;
      } catch(error) { lastError=error; recordApiHealth(source,false,Date.now()-startedAt); noteSourceFailure(source); }
    }
    if(!result)throw new Error(`${apiSources.length>1?'All configured APIs are unavailable':'API unavailable'}${lastError?.message?`: ${lastError.message}`:''}`);
    activeApiSource=result.source;
    updateActiveApiLabel();
    liveState.packets = mergeFeedPackets(result.packets);
    recordTrackedPacketCounters(liveState.packets);
    updateMyLog(liveState.packets);
    appStatsAccept(liveState.packets);
    appStatsSwitchBroker();
    await channelsDecryptLive(liveState.packets);
    mapIngest();
    channelStatsRefresh();
    liveState.error = ''; liveState.lastSuccess = Date.now(); pollFailures = 0;
  } catch (error) { liveState.error = error.message || 'Connection failed'; pollFailures++; }
  finally {
    liveState.loading = false;
    nextRefreshAt = Date.now() + (pollFailures ? Math.min(6000*2**(pollFailures-1),30000) : currentRefreshInterval());
    refreshLiveList();
    updateRefreshCountdown();
  }
  if(!liveState.error) enrichPacketObservations(liveState.packets,activeApiSource);
}
let lastCountdownText='';
function updateRefreshCountdown() {
  const countdown = document.getElementById('refresh-countdown');
  const text=`${Math.max(0, nextRefreshAt - Date.now())} ms`;
  if (countdown && text!==lastCountdownText) { countdown.textContent = text; lastCountdownText=text; }
  const button = document.getElementById('refresh-live-top');
  if (button && button.disabled!==liveState.loading) {
    button.disabled = liveState.loading;
    button.setAttribute('aria-busy', String(liveState.loading));
    button.title = liveState.loading ? 'Refreshing…' : 'Refresh packets now';
  }
}
function setText(element,text) { if(element&&element.textContent!==text)element.textContent=text; }
function updateLiveIndicators() {
  updateActiveApiLabel();
  // UPDATING is shown only for a slow request, so a normal poll never flickers the pill.
  const slow=liveState.loading&&Date.now()-loadingStartedAt>=UPDATING_GRACE_MS;
  setText(document.querySelector('.connection-pill span:last-child'),liveState.error?'OFFLINE':slow?'UPDATING':liveState.lastSuccess?'LIVE':'CONNECTING');
  document.querySelector('.connection-pill .status-dot')?.classList.toggle('offline',!!liveState.error);
  if(liveState.lastSuccess)setText(document.getElementById('last-updated'),`Updated ${new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(liveState.lastSuccess)}`);
}
function updateLiveAges() {
  if(currentScreen()!=='Live'||!liveDom.list?.isConnected)return;
  const byId=new Map(liveState.packets.map(packet=>[String(packet.id),packet]));
  for(const [id,entry] of liveDom.rows){ const packet=byId.get(id); if(packet)setRowAge(entry.el,packet); }
}
// ---------- Log zdrowia API (port ApiHealthLogStore/ApiHealthMonitor) ----------
const API_HEALTH_STORAGE='m2-web-api-health-v1';
let apiHealthLog=loadApiHealthLog();
function loadApiHealthLog() { try { const value=JSON.parse(sessionStorage.getItem(API_HEALTH_STORAGE)||'{}'); return value&&typeof value==='object'?value:{}; } catch { return {}; } }
function saveApiHealthLog() { try { sessionStorage.setItem(API_HEALTH_STORAGE,JSON.stringify(apiHealthLog)); } catch {} }
function recordApiHealth(source, ok, responseMs) {
  const host=sourceLabel(source), entries=apiHealthLog[host]||[];
  const status=ok?'ONLINE':'OFFLINE', last=entries[0];
  if(last&&last.status===status){ last.last=Date.now(); last.response=responseMs; last.checks=(last.checks||1)+1; }
  else entries.unshift({ start:Date.now(), last:Date.now(), status, response:responseMs, checks:1, ongoing:true });
  apiHealthLog[host]=entries.slice(0,250); saveApiHealthLog();
}
function resetApiHealthLog(source) { delete apiHealthLog[sourceLabel(source)]; saveApiHealthLog(); }

// ---------- Zamknięcie aplikacji (odpowiednik Close application z Androida) ----------
let appClosed=false;
function closeApplication() {
  appClosed=true;
  document.getElementById('intro')?.remove();
  const overlay=document.createElement('div');
  overlay.id='app-closed';
  overlay.innerHTML=`<img src="assets/m2-logo.svg" alt="M²"><h2>M² closed</h2><p>Background listening stopped.</p><button type="button" id="app-closed-reopen">Open again</button>`;
  document.body.appendChild(overlay);
  overlay.querySelector('#app-closed-reopen').addEventListener('click',()=>location.reload());
}
let settingsApiLogOpen=false;
function renderApiLogDialog() {
  const entries=apiHealthLog[sourceLabel(activeApiSource)]||[];
  const rows=entries.map(entry=>`<div class="api-log-row ${entry.status==='ONLINE'?'online':'offline'}"><b>${entry.status}</b><span>${escapeHtml(new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(entry.start))} – ${escapeHtml(new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(entry.last))}</span><span>${Number(entry.response)||0} ms · ${Number(entry.checks||1)} checks</span></div>`).join('');
  return `<div class="dialog-backdrop" id="api-log-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="API log"><h3>API log · ${escapeHtml(sourceLabel(activeApiSource))}</h3><div class="api-log-list">${rows||'<div class="empty-feed">No checks recorded yet.</div>'}</div><div class="dialog-actions"><button type="button" class="danger-link" id="api-log-reset">Reset</button><button type="button" class="dialog-cancel" id="api-log-close">Close</button></div></section></div>`;
}
function renderSettings() {
  screen.innerHTML = `<section class="settings-screen"><div class="eyebrow">PERSONALIZE M²</div><h1>Settings</h1><section class="api-settings"><div class="settings-heading"><h2>Packet APIs</h2><button type="button" id="open-api-log">Log</button></div><p class="settings-intro">The app tries these APIs in order. If the first one is unavailable, it switches automatically to the next working source.</p><div class="api-source-list">${apiSources.map((source,index)=>`<div class="api-source-row"><span class="api-order">${index+1}</span><code>${escapeHtml(source)}</code>${source===activeApiSource?'<b class="api-active-badge">ACTIVE</b>':''}<button type="button" data-primary-api="${index}" ${index===0?'disabled':''}>Make primary</button>${apiSources.length>1?`<button type="button" data-remove-api="${index}" aria-label="Remove API ${escapeHtml(source)}">Remove</button>`:''}</div>`).join('')}</div><div class="api-add-form"><label for="api-source-input">Add API base URL</label><div><input id="api-source-input" type="url" autocomplete="url" placeholder="https://api.example.org"><button id="add-api-source" type="button">Add API</button></div><p id="api-source-error" class="form-error" role="status" aria-live="polite"></p></div></section><section class="refresh-settings"><h2>Live refresh interval</h2><p class="settings-intro">Choose how often the packet feed is checked. The countdown next to LIVE follows this interval.</p><label for="refresh-interval">Refresh every</label><select id="refresh-interval">${REFRESH_OPTIONS.map(value=>`<option value="${value}" ${value===refreshIntervalMs?'selected':''}>${formatRefreshInterval(value)}</option>`).join('')}</select></section><section class="tracked-settings"><h2>Tracked keys</h2><p class="settings-intro">Add a full public key to recognize it in packet sources, observers and recorded routes.</p><div class="key-form"><label>Public key · 64 hex characters<input id="tracked-key" autocomplete="off" spellcheck="false" placeholder="Paste the full public key" maxlength="64"></label><button class="add-key-button" id="add-tracked-key" type="button">Add key</button><div id="key-form-error" class="form-error" role="status" aria-live="polite"></div></div><div class="key-storage-note"><span>SESSION ONLY</span> Keys and names are kept only for this browser session. Packet counts below use the loaded feed (${liveState.packets.length} of 250 packets).</div><div class="tracked-key-list"><div class="keys-heading"><strong>Saved keys</strong><span>${trackedKeys.length}</span></div>${trackedKeys.length?trackedKeys.map((item,index)=>`<div class="tracked-key-row"><div><strong>${escapeHtml(item.name||'Name unavailable')}</strong><code>${escapeHtml(item.key)}</code><small class="tracked-packet-count">${packetCountForTrackedKey(item.key)} matching packets in loaded feed</small></div><button type="button" data-remove-key="${index}" aria-label="Remove ${escapeHtml(item.name||'key')}">Remove</button></div>`).join(''):'<div class="empty-keys">No tracked keys yet.</div>'}</div></section><section class="about-settings"><h2>About M²</h2><p class="settings-intro">Exports (my log, maps) are saved to your browser's download folder. Channel keys never leave this browser.</p><a class="settings-link" href="https://ko-fi.com/beepoo304" target="_blank" rel="noopener noreferrer">Support M² on Ko-fi — ko-fi.com/beepoo304</a><a class="settings-link" href="https://github.com/beepoo304/M2_WEB" target="_blank" rel="noopener noreferrer">Open source on GitHub — github.com/beepoo304/M2_WEB</a><p class="version-note">M² Web version 0.3.0</p><button type="button" id="close-application" class="danger-button">Close application</button><p class="settings-intro">Stops background listening and closes M².</p></section></section>${settingsApiLogOpen?renderApiLogDialog():''}`;
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
  document.getElementById('open-api-log')?.addEventListener('click',()=>{ settingsApiLogOpen=true; renderSettings(); });
  document.getElementById('api-log-close')?.addEventListener('click',()=>{ settingsApiLogOpen=false; renderSettings(); });
  document.getElementById('api-log-backdrop')?.addEventListener('click',event=>{ if(event.target===event.currentTarget){ settingsApiLogOpen=false; renderSettings(); } });
  document.getElementById('api-log-reset')?.addEventListener('click',()=>{ resetApiHealthLog(activeApiSource); renderSettings(); });
  document.getElementById('close-application')?.addEventListener('click',closeApplication);
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
  screen.querySelector('.copy-source-key')?.addEventListener('click',event=>{if(liveState.selected)copyValue(detailKey(liveState.selected),event.currentTarget);});
  document.getElementById('clear-my-log')?.addEventListener('click',()=>{myLogPackets=[];saveMyLogPackets();renderMyLog();});
  document.getElementById('export-my-log')?.addEventListener('click',()=>{const content=myLogPackets.map(packet=>`${packetTime(packet)} · ${packetType(packet)} · ${liveIdentityLabel(packet)}\n${packetSummary(packet)}\nHash: ${packet.hash||'—'}\n`).join('\n');const blob=new Blob([content],{type:'text/plain'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`M2_MY_LOG_${new Date().toISOString().replace(/[:.]/g,'-')}.txt`;link.click();URL.revokeObjectURL(url);});
}
// ---------- Ekran Channels: pełny port z M² Android (ChannelsScreen.kt) ----------
const channelUiState={ add:false, addMode:null, namedPublic:false, input:'', invalid:false, renameTarget:'', renameText:'', statistics:false, appStatistics:false, details:null, detailsLoading:false };
function channelByIdentity(nameOrHash) { return savedChannels.find(item=>item.name===nameOrHash||String(item.hash).toLowerCase()===String(nameOrHash).toLowerCase()); }

function renderChannelAddDialog() {
  if(!channelUiState.add)return '';
  const mode=channelUiState.addMode;
  let body='';
  if(mode===null) body=`<p class="dialog-note">What kind of channel do you want to add?</p>
    <button type="button" class="dialog-option" id="channel-add-public"><b>Public channel</b><span>I know its name, for example #test</span></button>
    <button type="button" class="dialog-option" id="channel-add-private"><b>Private channel</b><span>I have a channel key or QR code</span></button>`;
  else if(mode==='public') {
    body=channelUiState.namedPublic
      ? `<p class="dialog-note">Enter the channel name</p><label class="dialog-field"><span>Channel name</span><div class="dialog-input"><b>#</b><input id="channel-name-input" autocomplete="off" spellcheck="false" value="${escapeHtml(channelUiState.input.replace(/^#/,''))}" placeholder="test"></div></label><p class="dialog-hint">${channelUiState.invalid?'Enter a channel name':'Example: #test'}</p>`
      : `<p class="dialog-note">Which public channel do you want to add?</p>
        <button type="button" class="dialog-option" id="channel-add-main-public"><b>Main public channel</b><span>The standard MeshCore public channel</span></button>
        <button type="button" class="dialog-option" id="channel-add-named"><b>Named public channel</b><span>For example #test or #bot</span></button>`;
  } else if(mode==='private') {
    body=`<p class="dialog-note">Paste the channel key or meshcore:// link</p>
      <label class="dialog-field"><span>Channel key</span><input id="channel-key-input" autocomplete="off" spellcheck="false" value="${escapeHtml(channelUiState.input)}" placeholder="32 or 64 hex characters"></label>
      <p class="dialog-hint">${channelUiState.invalid?'This key is not valid':'Private channels are decrypted locally; the key never leaves this browser.'}</p>`;
  }
  const confirmLabel=mode==='private'||(mode==='public'&&channelUiState.namedPublic)?'<button type="button" class="dialog-confirm" id="channel-add-confirm">Add channel</button>':'';
  return `<div class="dialog-backdrop" id="channel-add-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="Add channel"><h3>${mode==='public'?'Public channel':mode==='private'?'Private channel':'Add channel'}</h3>${body}<div class="dialog-actions">${confirmLabel}<button type="button" class="dialog-cancel" id="channel-add-cancel">${mode===null?'Cancel':'Back'}</button></div></section></div>`;
}

async function channelAddConfirm() {
  const nameEl = document.getElementById('channel-name-input');
  const keyEl = document.getElementById('channel-key-input');
  const rawInput = (channelUiState.addMode==='private' ? keyEl?.value : nameEl?.value) ?? channelUiState.input ?? '';
  const trimmed = String(rawInput).trim();
  const value = channelUiState.addMode==='private' ? trimmed : ('#' + trimmed.replace(/^#/, ''));
  const parsed = await M2Channels.parseChannel(value);
  if(!parsed){ channelUiState.invalid=true; renderChannels(); return; }
  const existing = savedChannels.find(item=>(item.secret||item.name)===value||item.name===parsed.name&&item.secret===parsed.secret);
  let channelObj = existing;
  if(!existing){
    channelObj = { ...parsed, lastReadAt:0, clearedAt:0, messages:[], loading:false, error:'', loaded:false };
    savedChannels.unshift(channelObj);
    if(savedChannels.length>50) savedChannels.length=50;
    saveChannels();
  }
  channelUiState.add=false; channelUiState.addMode=null; channelUiState.namedPublic=false; channelUiState.input=''; channelUiState.invalid=false;
  channelStatsRefresh();
  liveState.selectedChannel = channelObj.name;
  await channelsDecryptLive(liveState.packets);
  if(!channelObj.isPrivate) channelsLoadRemote(channelObj);
  renderChannels();
  if(currentScreen() === 'Live') renderLive();
}

function renderChannelMessageDetails() {
  if(!channelUiState.details)return '';
  const message=channelUiState.details, loading=channelUiState.detailsLoading;
  const route=loading?'<p class="details-loading">Loading message details…</p>'
    :`<dl class="details-list">
      <div><dt>Time</dt><dd>${escapeHtml(warsawDateTime(message.timestamp))}</dd></div>
      <div><dt>Hops</dt><dd>${Number(message.hops||0)}</dd></div>
      <div><dt>Route</dt><dd>${escapeHtml(message.route&&message.route.length?message.route.join(' → '):'Unavailable')}</dd></div>
      <div><dt>Seen</dt><dd>${Number(message.repeats||1)} observations</dd></div>
      <div><dt>Observers</dt><dd>${escapeHtml((message.observers||[]).join(', ')||'Unavailable')}</dd></div>
      <div><dt>Signal</dt><dd>${message.rssi==null?'—':`${message.rssi} dBm`} · ${message.snr==null?'—':`${message.snr} dB`}</dd></div>
      <div><dt>Packet</dt><dd class="mono">${escapeHtml(message.packetHash||message.id)}</dd></div>
    </dl>`;
  return `<div class="dialog-backdrop" id="channel-details-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="Message details"><h3>${escapeHtml(message.sender||'Anonymous')}</h3>${route}<div class="dialog-actions"><button type="button" class="dialog-cancel" id="channel-details-close">Close</button></div></section></div>`;
}

async function openChannelMessageDetails(message) {
  channelUiState.details={ ...message }; channelUiState.detailsLoading=true; renderChannels();
  let details={ ...message };
  try {
    const response=await fetch(apiProxyUrl('packet',{id:String(message.id)}),{cache:'no-store'});
    if(response.ok){
      const data=await response.json();
      const packet=data?.packet||{};
      let path=[];
      try{ path=Array.isArray(packet._parsedPath)?packet._parsedPath:JSON.parse(packet.path_json||'[]'); }catch{}
      details={ ...details, route:Array.isArray(path)?path:[], rssi:packet.rssi??details.rssi??null };
    }
  } catch {}
  channelUiState.details=details; channelUiState.detailsLoading=false; renderChannels();
}

function renderChannelStatistics() {
  const events=loadChannelStats();
  const selectedKey=channelUiState.statsKey||trackedKeys[0]?.key||'';
  const selectedEvents=events.filter(event=>String(event.key).toLowerCase()===selectedKey.toLowerCase());
  const grouped=new Map();
  selectedEvents.forEach(event=>{
    if(!grouped.has(event.channel))grouped.set(event.channel,[]);
    grouped.get(event.channel).push(event);
  });
  const orderedChannels=[...grouped.entries()].sort((a,b)=>Math.max(...b[1].map(messageEpochOf))-Math.max(...a[1].map(messageEpochOf)));
  const rows=orderedChannels.map(([channel,values])=>{
    const times=values.map(messageEpochOf);
    return `<div class="stats-group"><div class="stats-group-head"><b>${escapeHtml(channel)}</b><span>${values.length} packets</span></div>
      <small>First: ${escapeHtml(warsawDateTime(values.find(event=>messageEpochOf(event)===Math.min(...times))?.timestamp))}</small>
      <small>Last: ${escapeHtml(warsawDateTime(values.find(event=>messageEpochOf(event)===Math.max(...times))?.timestamp))}</small>
      <small>Sent ${values.filter(event=>event.sent).length} · Mentions ${values.filter(event=>event.mention).length}</small></div>`;
  }).join('');
  return `<section class="channels-screen"><div class="eyebrow">CHANNEL STATISTICS</div><h1>Channel statistics</h1>
    <label class="dialog-field"><span>Tracked key</span><select id="stats-key">${trackedKeys.map(item=>`<option value="${escapeHtml(item.key)}" ${item.key===selectedKey?'selected':''}>${escapeHtml(item.key.slice(0,4).toUpperCase())} · ${escapeHtml(item.name||'Unnamed')}</option>`).join('')||'<option value="">Add a tracked key first</option>'}</select></label>
    <div class="stats-totals"><div><b>${selectedEvents.filter(event=>event.sent).length}</b><span>Sent</span></div><div><b>${selectedEvents.filter(event=>event.mention).length}</b><span>Mentions</span></div><div><b>${grouped.size}</b><span>Channels</span></div></div>
    ${selectedEvents.length?`<button type="button" class="danger-link" id="stats-reset">Reset</button>`:''}
    <div class="stats-list">${rows||'<div class="empty-feed">No related channel traffic in the last 24 hours.</div>'}</div>
    <button type="button" class="back-link" id="stats-back">← Channels</button></section>`;
}

function renderAppStatistics() {
  return `<section class="channels-screen"><div class="eyebrow">APP PACKET STATISTICS</div><h1>App packet statistics</h1>
    <dl class="details-list">
      <div><dt>Started</dt><dd>${escapeHtml(warsawDateTime(new Date(appStats.startedAtMs).toISOString()))}</dd></div>
      <div><dt>Packets received</dt><dd class="stats-big">${Number(appStats.packetCount).toLocaleString('en-US')}</dd></div>
      <div><dt>Total app running time</dt><dd>${escapeHtml(formatRunningTime(appStats.accumulatedRunningMs))}</dd></div>
    </dl>
    ${Object.entries(appStats.brokerRunningMs).map(([broker,ms])=>`<p class="broker-time">${escapeHtml(broker)} <b>${escapeHtml(formatRunningTime(ms))}</b></p>`).join('')}
    <button type="button" class="danger-link" id="app-stats-reset">Reset</button>
    <button type="button" class="back-link" id="app-stats-back">← Channels</button></section>`;
}

async function renderChannels() {
  if(channelUiState.appStatistics){ renderChannelsAppStats(); return; }
  if(channelUiState.statistics){ renderChannelsStats(); return; }
  const selected=liveState.selectedChannel;
  const channel=selected?channelByIdentity(selected):null;
  if(channel&&!channel.isPrivate&&!channel.loaded&&!channel.loading){ channel.loaded=true; channelsLoadRemote(channel); }
  if(channel){ channel.lastReadAt=Date.now(); saveChannels(); }
  const trackedNames=trackedNamesLower();
  const orderedChannels=[...savedChannels].sort((a,b)=>{
    const aTracked=(a.messages||[]).some(message=>trackedNames.some(name=>String(message.sender||'').trim().toLowerCase()===name))||false;
    const bTracked=(b.messages||[]).some(message=>trackedNames.some(name=>String(message.sender||'').trim().toLowerCase()===name))||false;
    if(aTracked!==bTracked)return aTracked?-1:1;
    return Math.max(0,...(b.messages||[]).map(messageEpochOf))-Math.max(0,...(a.messages||[]).map(messageEpochOf));
  });
  const list=orderedChannels.map(item=>{
    const unread=(item.messages||[]).filter(message=>messageEpochOf(message)>Number(item.lastReadAt||0));
    const trackedUnread=unread.filter(messageIsTracked).length, otherUnread=unread.length-trackedUnread;
    return `<div class="channel-row" data-channel="${escapeHtml(item.name)}">
      <button class="channel-open" type="button"><b>${escapeHtml(item.name)}${item.isPrivate?' 🔑':''}</b><span>${escapeHtml(String(item.hash||'').slice(0,2))} · ${item.loading?'Loading…':item.error?'Error':`${(item.messages||[]).length} messages`}</span></button>
      ${trackedUnread?`<b class="unread-badge tracked">${trackedUnread}</b>`:''}${otherUnread?`<b class="unread-badge">${otherUnread}</b>`:''}
      ${item.isPrivate?`<button type="button" data-rename-channel="${escapeHtml(item.name)}" title="Rename channel">✎</button>`:''}
      <button type="button" data-remove-channel="${escapeHtml(item.name)}" title="Remove channel">🗑</button>
    </div>`;
  }).join('');
  const messages=channel?.messages||[];
  const messageList=channel?(channel.loading?'<div class="empty-feed">Loading messages…</div>':channel.error?`<div class="feed-error"><strong>Channel unavailable</strong><span>${escapeHtml(channel.error)}</span></div>`:messages.map(message=>{
    const tracked=messageIsTracked(message);
    return `<article class="channel-message ${tracked?'tracked':''}" data-message-id="${escapeHtml(message.id)}"><b>${renderTrackedText(message.sender)}</b><small>${escapeHtml(warsawDateTime(message.timestamp))} · ${Number(message.hops||0)} hops</small><p>${renderTrackedText(message.text||'')}</p></article>`;
  }).join('')||'<div class="empty-feed">No messages received.</div>'):'';
  screen.innerHTML=`<section class="channels-screen"><div class="eyebrow">SAVED CHANNELS</div><h1>${channel?escapeHtml(channel.name):'Channels'}</h1>
    ${channel?`<div class="channel-view-head"><button id="back-channels" type="button">← All channels</button><div><button type="button" id="channel-refresh">↻ Refresh</button><button type="button" id="channel-clear" ${messages.length?'':'disabled'}>Delete all</button></div><span>${messages.length} messages</span></div><div class="channel-messages">${messageList}</div>`
    :`<button type="button" class="add-channel-tile" id="open-add-channel">＋ Add channel</button>
      ${savedChannels.length?`<div class="channel-list">${list}</div>`:'<div class="empty-feed">Channels you add will appear here.</div>'}
      <button type="button" class="stats-tile" id="open-channel-stats">Channel statistics</button>
      <button type="button" class="stats-tile" id="open-app-stats">App packet statistics</button>`}
  </section>${renderChannelAddDialog()}${renderChannelMessageDetails()}${channelUiState.renameTarget?`<div class="dialog-backdrop" id="channel-rename-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="Rename channel"><h3>Channel name</h3><label class="dialog-field"><span>Local name</span><input id="channel-rename-input" value="${escapeHtml(channelUiState.renameText)}"></label><div class="dialog-actions"><button type="button" class="dialog-confirm" id="channel-rename-save">Save</button><button type="button" class="dialog-cancel" id="channel-rename-cancel">Cancel</button></div></section></div>`:''}`;
  document.getElementById('open-add-channel')?.addEventListener('click',()=>{ channelUiState.add=true; channelUiState.addMode=null; channelUiState.namedPublic=false; channelUiState.input=''; channelUiState.invalid=false; renderChannels(); });
  document.getElementById('channel-add-public')?.addEventListener('click',()=>{ channelUiState.addMode='public'; channelUiState.namedPublic=false; channelUiState.input=''; channelUiState.invalid=false; renderChannels(); });
  document.getElementById('channel-add-private')?.addEventListener('click',()=>{ channelUiState.addMode='private'; channelUiState.input=''; channelUiState.invalid=false; renderChannels(); });
  document.getElementById('channel-add-main-public')?.addEventListener('click',async()=>{ const parsed=await M2Channels.parseChannel('public'); if(!savedChannels.some(item=>item.name==='public')){ savedChannels.unshift({ ...parsed, lastReadAt:0, clearedAt:0, messages:[], loading:false, error:'' }); saveChannels(); } channelUiState.add=false; channelUiState.addMode=null; channelUiState.namedPublic=false; renderChannels(); });
  document.getElementById('channel-add-named')?.addEventListener('click',()=>{ channelUiState.namedPublic=true; channelUiState.input=''; channelUiState.invalid=false; renderChannels(); });
  const nameInput=document.getElementById('channel-name-input');
  nameInput?.addEventListener('input',()=>{ channelUiState.input=nameInput.value; channelUiState.invalid=false; });
  nameInput?.addEventListener('keydown',event=>{ if(event.key==='Enter')channelAddConfirm(); });
  const keyInput=document.getElementById('channel-key-input');
  keyInput?.addEventListener('input',()=>{ channelUiState.input=keyInput.value.trim(); channelUiState.invalid=false; });
  keyInput?.addEventListener('keydown',event=>{ if(event.key==='Enter')channelAddConfirm(); });
  document.getElementById('channel-add-confirm')?.addEventListener('click',channelAddConfirm);
  document.getElementById('channel-add-cancel')?.addEventListener('click',()=>{
    if(channelUiState.addMode===null)channelUiState.add=false;
    else if(channelUiState.addMode==='public'&&channelUiState.namedPublic){ channelUiState.namedPublic=false; channelUiState.input=''; }
    else { channelUiState.addMode=null; channelUiState.namedPublic=false; channelUiState.input=''; }
    channelUiState.invalid=false; renderChannels();
  });
  document.getElementById('channel-add-backdrop')?.addEventListener('click',event=>{ if(event.target===event.currentTarget){ channelUiState.add=false; channelUiState.addMode=null; channelUiState.namedPublic=false; channelUiState.invalid=false; renderChannels(); } });
  document.getElementById('back-channels')?.addEventListener('click',()=>{ liveState.selectedChannel=''; renderChannels(); });
  document.getElementById('channel-refresh')?.addEventListener('click',()=>{ if(channel){ if(!channel.isPrivate)channelsLoadRemote(channel); if(channel.secret)channelsDecryptLive(liveState.packets); } });
  document.getElementById('channel-clear')?.addEventListener('click',()=>{ if(channel){ channel.messages=[]; channel.clearedAt=Date.now(); saveChannels(); channelStatsRefresh(); renderChannels(); } });
  document.getElementById('channel-details-close')?.addEventListener('click',()=>{ channelUiState.details=null; renderChannels(); });
  document.getElementById('channel-details-backdrop')?.addEventListener('click',event=>{ if(event.target===event.currentTarget){ channelUiState.details=null; renderChannels(); } });
  document.getElementById('stats-key')?.addEventListener('change',event=>{ channelUiState.statsKey=event.target.value; renderChannelsStats(); });
  document.getElementById('stats-reset')?.addEventListener('click',()=>{ channelStatsReset(channelUiState.statsKey||trackedKeys[0]?.key||''); renderChannelsStats(); });
  document.getElementById('stats-back')?.addEventListener('click',()=>{ channelUiState.statistics=false; renderChannels(); });
  document.getElementById('app-stats-reset')?.addEventListener('click',()=>{ if(confirm('Reset app packet statistics? The packet counter, start date and accumulated running time will start again from zero.')){ appStatsReset(); renderChannelsAppStats(); } });
  document.getElementById('app-stats-back')?.addEventListener('click',()=>{ channelUiState.appStatistics=false; renderChannels(); });
  document.getElementById('open-channel-stats')?.addEventListener('click',()=>{ channelUiState.statistics=true; channelStatsRefresh(); renderChannelsStats(); });
  document.getElementById('open-app-stats')?.addEventListener('click',()=>{ channelUiState.appStatistics=true; renderChannelsAppStats(); });
  document.getElementById('channel-rename-save')?.addEventListener('click',()=>{ const target=channelByIdentity(channelUiState.renameTarget); if(target){ target.name=channelUiState.renameText.trim()||target.name; saveChannels(); } channelUiState.renameTarget=''; renderChannels(); });
  document.getElementById('channel-rename-cancel')?.addEventListener('click',()=>{ channelUiState.renameTarget=''; renderChannels(); });
  screen.querySelectorAll('.channel-open').forEach(button=>button.addEventListener('click',()=>{ liveState.selectedChannel=button.closest('[data-channel]').dataset.channel; renderChannels(); }));
  screen.querySelectorAll('[data-remove-channel]').forEach(button=>button.addEventListener('click',event=>{ event.stopPropagation(); savedChannels=savedChannels.filter(item=>item.name!==button.dataset.removeChannel); saveChannels(); channelStatsRefresh(); renderChannels(); }));
  screen.querySelectorAll('[data-rename-channel]').forEach(button=>button.addEventListener('click',event=>{ event.stopPropagation(); channelUiState.renameTarget=button.dataset.renameChannel; channelUiState.renameText=button.dataset.renameChannel; renderChannels(); }));
  screen.querySelectorAll('.channel-message').forEach(article=>article.addEventListener('click',()=>{ const message=(channel?.messages||[]).find(item=>String(item.id)===article.dataset.messageId); if(message)openChannelMessageDetails(message); }));
}
function renderChannelsStats() {
  screen.innerHTML=renderChannelStatistics();
  document.getElementById('stats-key')?.addEventListener('change',event=>{ channelUiState.statsKey=event.target.value; renderChannelsStats(); });
  document.getElementById('stats-reset')?.addEventListener('click',()=>{ channelStatsReset(channelUiState.statsKey||trackedKeys[0]?.key||''); renderChannelsStats(); });
  document.getElementById('stats-back')?.addEventListener('click',()=>{ channelUiState.statistics=false; renderChannels(); });
}
function renderChannelsAppStats() {
  screen.innerHTML=renderAppStatistics();
  document.getElementById('app-stats-reset')?.addEventListener('click',()=>{ if(confirm('Reset app packet statistics? The packet counter, start date and accumulated running time will start again from zero.')){ appStatsReset(); renderChannelsAppStats(); } });
  document.getElementById('app-stats-back')?.addEventListener('click',()=>{ channelUiState.appStatistics=false; renderChannels(); });
}
function renderPlaceholder(name) {
  const descriptions = {'My log':'A focused log of packets related to the public keys you save in Settings.','Channels':'Public and locally decrypted private channels, with the M² channel tools.','Map':'Tracked packet routes, repeaters, distances and the longest-route flight.','Settings':'Saved devices, API selection, refresh behaviour and web-session key controls.','Guide':'Packet types, route colours, map modes and network-data notes.'};
  screen.innerHTML = `<section class="welcome-panel"><div class="eyebrow">${escapeHtml(name.toUpperCase())}</div><h1>${escapeHtml(name)}</h1><p>${escapeHtml(descriptions[name])}</p></section>`;
}
function currentScreen() { return document.querySelector('.nav-item.active')?.dataset.screen || 'Live'; }
function renderScreen(name) { document.body.classList.toggle('map-fullscreen',name==='Map'); if(name!=='Map'&&typeof leaveMap==='function')leaveMap(); if(name==='Live')renderLive();else if(name==='My log')renderMyLog();else if(name==='Channels')renderChannels();else if(name==='Map')renderMap();else if(name==='Settings')renderSettings();else if(name==='Guide')renderGuide();else renderPlaceholder(name); }
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
loadPackets().then(() => syncChannelSecrets());
document.getElementById('refresh-live-top')?.addEventListener('click', () => loadPackets(true));
setInterval(() => {
  if(appClosed) return;
  if(Date.now() >= nextRefreshAt && !liveState.loading) loadPackets(false);
  if(!document.hidden) { updateRefreshCountdown(); if(liveState.loading) updateLiveIndicators(); }
}, 250);
setInterval(() => { if(!document.hidden) updateLiveAges(); }, 1000);
document.addEventListener('visibilitychange', () => {
  // Back in the foreground: refresh now instead of waiting out the slow hidden interval.
  if(!document.hidden && !liveState.loading) { nextRefreshAt=Math.min(nextRefreshAt,Date.now()+refreshIntervalMs); if(Date.now()-liveState.lastSuccess>=refreshIntervalMs) loadPackets(); }
});

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
