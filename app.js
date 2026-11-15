const tabButtons = [...document.querySelectorAll('.nav-item')];
const screen = document.getElementById('screen');
const liveState = { packets: [], loading: false, error: '', lastSuccess: 0, selected: null, details: null, detailsLoading: false, detailsError: '', selectedChannel: '', showAllRoutes: false };
// Mirrors MÂ˛'s observation-match cache: a packet is rechecked only if its
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

function safeText(value, fallback = 'â€”') { return value == null || value === '' ? fallback : String(value); }

function showToast(message) {
  // Simple toast notification â€“ appears for a few seconds.
  const existing = document.getElementById('agy-toast-style');
  if (!existing) {
    const style = document.createElement('style');
    style.id = 'agy-toast-style';
    style.textContent = `
      .agy-toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: rgba(0,0,0,0.8);
        color: #fff;
        padding: 10px 15px;
        border-radius: 4px;
        font-family: sans-serif;
        font-size: 14px;
        z-index: 10000;
        opacity: 0;
        transition: opacity 0.3s ease-in-out;
      }
      .agy-toast.show { opacity: 1; }
    `;
    document.head.appendChild(style);
  }
  const toast = document.createElement('div');
  toast.className = 'agy-toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function parseDecoded(packet) {
  if (packet._decoded && typeof packet._decoded === 'object') return packet._decoded;
  try { packet._decoded = typeof packet.decoded_json === 'string' ? JSON.parse(packet.decoded_json) : (packet.decoded_json || {}); }
  catch { packet._decoded = {}; }
  return packet._decoded;
}
function packetType(packet) { return labels[Number(packet.payload_type)] || `UNKNOWN ${safeText(packet.payload_type, '?')}`; }
function packetTime(packet) {
  const date = new Date(packet.timestamp || packet.first_seen);
  if (Number.isNaN(date.getTime())) return 'â€”';
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
  if (type === 5) return `${safeText(decoded.channel, 'Private channel')} Â· ${safeText(decoded.text, 'Message content unavailable')}`;
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
  // MÂ˛ keeps every API path entry intact. In particular, adjacent 1-byte
  // entries must never be merged: doing so corrupts a trace route.
  return Array.isArray(raw) ? raw.map(hop=>String(hop||'').trim().toUpperCase()) : [];
}
function pathSummary(packet) {
  const path = packetPath(packet);
  if (!path.length) return 'direct';
  if (path.some(hop => String(hop).length === 2)) return '1-byte route';
  return `${path.length} hops`;
}
function keyName(key) { return trackedKeys.find(item=>item.key.toLowerCase()===String(key||'').toLowerCase())?.name || `${String(key||'').slice(0,4).toUpperCase()}â€¦`; }
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
    // MÂ˛ counts a decoded destination as own traffic, but does not render it as a reply label.
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
  // flat(2): routeMatches to tablica tablic â€” jeden poziom nie wystarcza,
  // bo pusta trasa ([]) trafiĹ‚aby do wyniku jako â€žmatch" bez klucza.
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
// KanaĹ‚y sÄ… trwaĹ‚e (localStorage) jak w MÂ˛ Android; stary format sesyjny jest migrowany.
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

/** Deszyfracja wiadomoĹ›ci prywatnych kanaĹ‚Ăłw z bieĹĽÄ…cego strumienia pakietĂłw (payload_type 5). */
async function channelsDecryptLive(packets) {
  const keyed=savedChannels.filter(channel=>channel.secret);
  if(!keyed.length)return;
  let changed=false;
  for(const packet of (Array.isArray(packets)?packets:[])) {
    if(Number(packet.payload_type)!==5)continue;
    const decoded=parseDecoded(packet);
    const channelHashHex=String(decoded.channelHashHex||'');
    const encrypted=String(decoded.encryptedData||''), mac=String(decoded.mac||'');
    if(!channelHashHex||!encrypted||!mac)continue;
    for(const channel of keyed) {

        if(!(await M2Channels.validMac(channel.secret,mac,encrypted))){
          showToast(`Invalid MAC for channel ${channel.name}`);
          continue;
        }
        const message=await M2Channels.decryptMessage(channel.secret,encrypted);
        if(!message){
          showToast(`Failed to decrypt message for channel ${channel.name}`);
          continue;
        }
      const incoming={ id:String(packet.id), sender:message.sender, text:message.text, timestamp:message.timestamp,
        hops:packetPath(packet).length, observers:[packet.observer_name].filter(Boolean),
        repeats:Number(packet.observation_count||1), snr:packet.snr??null, packetHash:packet.hash||'' };
      const merged=M2Channels.mergeMessages(channel.messages,[incoming],channel.clearedAt);
      if(merged.length!==channel.messages.length||merged[0]?.id!==channel.messages[0]?.id){ channel.messages=merged; changed=true; }
    }
  }
  if(changed){ saveChannels(); channelStatsRefresh(); if(currentScreen()==='Channels')renderChannels(); }
}

/** WiadomoĹ›ci kanaĹ‚u bez sekretu (public / #nazwa) â€” pobierane z API jak w Androidzie. */
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
  return Number.isNaN(date.getTime())?'â€”':new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(date);
}

// ---------- Statystyki kanaĹ‚Ăłw (port ChannelStatisticsEngine, okno 24 h) ----------
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

// ---------- Statystyki pakietĂłw aplikacji (port AppPacketStatisticsEngine) ----------
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
  if(!Number.isFinite(time)||time<=0)return 'â€”';
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
  return Number.isFinite(time) ? new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Warsaw',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(time) : 'â€”';
}
function metric(value, digits=2) { const number=Number(value); return Number.isFinite(number) ? number.toFixed(digits) : 'â€”'; }
function closeNodeInfo() { document.querySelector('.node-info-backdrop')?.remove(); }
function rptMetricHelp(key) {
  return {
    role:{pl:'Rola tego wÄ™zĹ‚a w sieci MeshCore: repeater przekazuje dalej pakiety, companion to zwykĹ‚e urzÄ…dzenie mobilne, sensor raportuje dane, a room server utrzymuje kanaĹ‚.',en:'The role of this node in the MeshCore network: repeater relays packets, companion is a regular mobile device, sensor reports data, room server hosts a channel.'},
    lastHeard:{pl:'Czas od ostatniego pakietu wysĹ‚anego przez ten wÄ™zeĹ‚, ktĂłry byĹ‚ widoczny dla co najmniej jednego listenera.',en:'Time since the last packet sent by this node was seen by at least one listener.'},
    usefulness:{pl:'Punktowy wskaĹşnik jakoĹ›ci tego wÄ™zĹ‚a, scalajÄ…cy ruch, tĹ‚umienie, redundancjÄ™ i zasiÄ™g.',en:'A point score for this node, combining traffic, attenuation, redundancy and coverage.'},
    traffic:{pl:'KaĹĽdy sĹ‚uchacz widzi czÄ™Ĺ›Ä‡ sieci; udziaĹ‚ w ruchu to procent widzianych pakietĂłw.',en:'Each listener sees part of the network; traffic share is the percentage of packets seen.'},
    bridge:{pl:'PoĹ‚Ä…czenie miÄ™dzy rĂłĹĽnymi sub-mesh â€” wÄ™zeĹ‚ z wysokim wynikiem utrzymuje poĹ‚Ä…czenie miÄ™dzy obszarami z sĹ‚abym zasiÄ™giem.',en:'Linking different sub-mesh â€” a high-scoring node keeps distant areas connected.'},
    coverage:{pl:'Jak dobry jest odbiĂłr dla obszaru geograficznego obsĹ‚ugiwanego przez ten wÄ™zeĹ‚.',en:'How good the reception is for the geographic area served by this node.'},
    redundancy:{pl:'WÄ™zeĹ‚ poĹ›redniczÄ…cy â€” jeĹ›li inne wÄ™zĹ‚y z wysokim wynikiem zaniknÄ…, ten przejmie Ĺ›wiadczenie usĹ‚ug w zasiÄ™gu.',en:'A middle node â€” if other high-scoring nodes disappear, this node takes over service in range.'},
    firstSeen:{pl:'Kiedy ten wÄ™zeĹ‚ byĹ‚ widziany po raz pierwszy w API.',en:'When this node was first seen in the API.'},
    totalPackets:{pl:'KaĹĽdy sĹ‚uchacz widzi czÄ™Ĺ›Ä‡ sieci; total packets to suma pakietĂłw widzianych przez nasze API.',en:'Each listener sees part of the network; total packets is the sum seen by our API.'},
    packetsToday:{pl:'KaĹĽdy sĹ‚uchacz widzi czÄ™Ĺ›Ä‡ sieci; pakiety dziĹ› to suma widzianych dziĹ› pakietĂłw.',en:'Each listener sees part of the network; packets today is the sum seen today.'},
    avgSnr:{pl:'Ĺšrednia moc sygnaĹ‚u nadawania przez ten wÄ™zeĹ‚; niĹĽsze dBm to silniejszy sygnaĹ‚.',en:'The average power used by this node to transmit; lower dBm is stronger.'},
    avgHops:{pl:'Ĺšrednia liczba wÄ™zĹ‚Ăłw poĹ›redniczÄ…cych potrzebna, ĹĽeby dostarczyÄ‡ pakiet do tego wÄ™zĹ‚a.',en:'The average number of middle nodes needed to deliver a packet to this node.'}
  }[key]||null;
}
function renderRptHelp(key) {
  if(!rptMetricHelp(key))return '';
  return `<button type="button" class="metric-help" data-rpt-help="${escapeHtml(key)}" aria-label="About ${escapeHtml(key)}">â“</button>`;
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
  const statusText=loading?'â€¦':error?'':active?'ACTIVE':'INACTIVE';
  const body=loading ? '<p class="details-loading">Loading RPT information and recorded neighboursâ€¦</p>' : error ? `<p class="details-error">${escapeHtml(error)}</p>` : `<section class="node-info-grid"><div class="${active?'status-active':''}"><span>STATUS${renderRptHelp('role')}</span><b>${statusText}</b></div><div><span>ROLE</span><b>${escapeHtml(node.role||'â€”')}</b></div><div><span>LAST HEARD${renderRptHelp('lastHeard')}</span><b>${escapeHtml(nodeInfoDate(node.last_heard||node.last_seen))}</b></div><div><span>USEFULNESS${renderRptHelp('usefulness')}</span><b>${escapeHtml(metric(node.usefulness_score))}${node.usefulness_grade?` Â· ${escapeHtml(node.usefulness_grade)}`:''}</b></div><div><span>TRAFFIC SHARE${renderRptHelp('traffic')}</span><b>${escapeHtml(metric(node.traffic_share_score))}</b></div><div><span>BRIDGE SCORE${renderRptHelp('bridge')}</span><b>${escapeHtml(metric(node.bridge_score))}</b></div><div><span>COVERAGE${renderRptHelp('coverage')}</span><b>${escapeHtml(metric(node.coverage_score))}</b></div><div><span>REDUNDANCY${renderRptHelp('redundancy')}</span><b>${escapeHtml(metric(node.redundancy_score))}</b></div><div><span>FIRST SEEN${renderRptHelp('firstSeen')}</span><b>${escapeHtml(nodeInfoDate(node.first_seen))}</b></div><div><span>TOTAL PACKETS${renderRptHelp('totalPackets')}</span><b>${Number(stats.totalPackets||0).toLocaleString('en-US')}</b></div><div><span>PACKETS TODAY${renderRptHelp('packetsToday')}</span><b>${Number(stats.packetsToday||0).toLocaleString('en-US')}</b></div><div><span>AVG. SNR${renderRptHelp('avgSnr')}</span><b>${stats.avgSnr==null?'â€”':`${metric(stats.avgSnr,1)} dB`}</b></div><div><span>AVG. HOPS${renderRptHelp('avgHops')}</span><b>${stats.avgHops==null?'â€”':metric(stats.avgHops,1)}</b></div></section><section class="neighbour-list"><h3>RECORDED NEIGHBOURS Â· ${neighbours.length}</h3>${neighbours.length?neighbours.map(neighbour=>`<div><code>${escapeHtml(neighbour.hash)}</code><b>${escapeHtml(neighbour.name)}</b><span>${Number(neighbour.count||0)} routes</span></div>`).join(''):'<p>No reliable neighbour route was found.</p>'}</section>`;
  document.body.insertAdjacentHTML('beforeend',`<div class="node-info-backdrop"><section class="node-info-dialog" role="dialog" aria-modal="true" aria-label="RPT information"><button class="detail-close node-info-close" aria-label="Close RPT information"><span aria-hidden="true">Ă—</span><b>Close</b></button><div class="eyebrow">RPT INFO Â· ${escapeHtml(sourceLabel(activeApiSource))}</div><h2>${escapeHtml(node.name||item.name||'Tracked device')}</h2><p class="node-info-key">${escapeHtml(item.key)}</p>${body}</section></div>`);
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
      <span class="packet-copy"><strong>${liveIdentityMarkup(packet)}</strong>${packetPath(packet).some(hop=>String(hop).length===2&&/^[a-f\d]{2}$/i.test(String(hop)))?'<small class="one-byte-marker">1 byte</small>':''}<span>${renderTrackedText(preview)}</span><small>${escapeHtml(packet.observer_iata || 'Observer')} Â· ${Number(packet.observation_count || 1)} observation${Number(packet.observation_count || 1) === 1 ? '' : 's'}</small>${missingGpsHashes(packet).map(hash=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hash)}</b>`).join('')}${matches.length?`<span class="key-match-list">${matches.map(match=>`<b class="${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} Â· ${escapeHtml(match.name || keyName(match.key))}</b>${match.relation===trackedRelations.reply&&replyHasNoRoute(packet,match.key)?'<b class="no-route">NO ROUTE</b>':''}`).join('')}</span>`:''}</span>
      <span class="packet-route">${escapeHtml(pathSummary(packet))}<small>${packet.rssi == null ? '' : `${escapeHtml(packet.rssi)} dBm`}</small></span>
    </button>`;
  }).join('');
  const last = liveState.lastSuccess ? new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(liveState.lastSuccess) : 'â€”';
  screen.innerHTML = `<section class="live-screen">
    <div class="live-heading"><div><div class="eyebrow">MESHCORE NETWORK</div><h1>Live packets</h1><p>Packets observed across the public MeshCore feed.</p></div></div>
    <div class="live-meta"><span class="live-count">${liveState.packets.length} / 250 packets</span><span id="last-updated">Updated ${last}</span></div>
    ${liveState.error ? `<div class="feed-error"><strong>Feed temporarily unavailable</strong><span>${escapeHtml(liveState.error)}</span></div>` : ''}
    <div class="packet-list">${rows || `<div class="empty-feed">${liveState.loading?'Connecting to the live feedâ€¦':'No packets received yet.'}</div>`}</div>
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
    ['Path', path.length ? path.join('  â€ş  ') : 'Direct / no path'], ['RSSI', packet.rssi == null ? null : `${packet.rssi} dBm`], ['SNR', packet.snr == null ? null : `${packet.snr} dB`],
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
    }).join(' <span class="route-arrow">â€ş</span> ');
    const noGps=route.path.filter((hop,index)=>confirmedMissingGps(hop,route.resolved[index]||'')).map(hop=>String(hop).slice(0,4).toUpperCase());
    const observerMarkup=route.observers.map(item=>{
      const matches=relationMatches({...source,path_json:JSON.stringify(route.path),resolved_path:route.resolved,observer_id:item.observer_id});
      const reported=matches.some(match=>match.relation===trackedRelations.observer);
      const observerMatch=matches.find(match=>match.relation===trackedRelations.observer);
      const observerKey=reported ? ` Â· ${escapeHtml(String(observerMatch?.key||'').slice(0,4).toUpperCase())}` : '';
      const rssi=item.rssi==null?'RSSI â€”':`${escapeHtml(item.rssi)} dBm`;
      const snr=item.snr==null?'SNR â€”':`${escapeHtml(item.snr)} dB`;
      const relationMarkup=matches.map(match=>`<b class="relation-chip ${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} Â· ${escapeHtml(match.name||keyName(match.key))}</b>`).join('');
      return `<div class="route-observer ${reported?'tracked-observer':''}">Observed by ${escapeHtml(item.observer_name||'Unknown observer')}${observerKey} Â· ${escapeHtml(item.observer_iata||'â€”')} Â· ${rssi} Â· ${snr}${relationMarkup}</div>`;
    }).join('');
    const gpsMarkup=noGps.map(hash=>`<b class="no-gps">NO GPS FOR ${escapeHtml(hash)}</b>`).join('');
    return `<div class="observed-route">${gpsMarkup}<code>${chain||'Direct / no route'}</code><small>${Math.max(0,route.path.length-1)} hops Â· ${route.observers.length} observation${route.observers.length===1?'':'s'}</small>${observerMarkup}</div>`;
  }).join('');
  const sourceKey=decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey;
  return `<div class="packet-detail-backdrop"><section class="packet-detail" role="dialog" aria-modal="true" aria-label="Packet details"><button class="detail-close" aria-label="Close packet details"><span aria-hidden="true">Ă—</span><b>Close</b></button><div class="eyebrow">PACKET DETAILS Â· ${escapeHtml(packetType(packet))} Â· ${(packet.direction || 'rx').toUpperCase()}</div><h2>${escapeHtml(decoded.sender || decoded.name || 'Mesh packet')}</h2><p class="detail-message">${escapeHtml(packetSummary(source))}</p>${matches.length?`<div class="detail-key-matches">${matches.map(match=>`<b class="relation-chip ${match.relation===trackedRelations.reply?'reply':''}">${escapeHtml(match.relation)} Â· ${escapeHtml(match.name||keyName(match.key))}</b>`).join('')}</div>`:''}<dl>${fields.map(([key,value])=>`<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>${liveState.detailsLoading?'<p class="details-loading">Loading all observations and routesâ€¦</p>':''}${liveState.detailsError?`<p class="details-error">Could not load additional routes: ${escapeHtml(liveState.detailsError)}</p>`:''}${excludedOneByteRoutes?`<p class="route-excluded-note">1-byte routes excluded: ${excludedOneByteRoutes}</p>`:''}${eligibleRoutes.length?`<section class="observed-routes"><h3>${trackedRoutes.length&&!showAllRoutes?'TRACKED ROUTES':'OBSERVED ROUTES'} Â· ${displayedRoutes.length} ROUTES / ${observations.length} OBSERVATIONS</h3>${hashWidth?`<p class="route-hash-width">Path hashes: ${hashWidth} ${hashWidth===1?'byte':'bytes'} per hop</p>`:''}${routeMarkup}${trackedRoutes.length<eligibleRoutes.length?`<button class="route-toggle" type="button">${showAllRoutes?'Show tracked routes':`Show all ${eligibleRoutes.length} routes`}</button>`:''}</section>`:''}${decodedFields.length?`<div class="decoded-block"><span>DECODED FIELDS</span>${decodedFields.map(([key,value])=>`<div><b>${escapeHtml(key)}</b><code>${escapeHtml(typeof value==='object'?JSON.stringify(value):value)}</code></div>`).join('')}</div>`:''}${packet.raw_hex?`<div class="raw-block"><span>RAW HEX</span><code>${escapeHtml(packet.raw_hex)}</code></div>`:''}<div class="detail-actions"><button class="copy-packet-hash" type="button">Copy packet hash</button><button class="detail-close-secondary" type="button">Close packet</button>${sourceKey?'<button class="copy-source-key" type="button">Copy source key</button>':''}</div></section></div>`;
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
  mapIngest();
  if(source===activeApiSource && currentScreen()==='Live' && !liveState.selected) renderLive();
}
async function loadPackets(manual = false) {
  if (liveState.loading || document.hidden || appClosed) return;
  const previousIds=liveState.packets.map(item=>item.id).join(','), previousError=liveState.error;
  liveState.loading = true; if(manual) renderLive();
  try {
    let lastError=null, result=null;
    for(const source of apiSources){
      const startedAt=Date.now();
      try {
        const response=await fetch(apiProxyUrl('packets',{limit:'250'},source),{cache:'no-store'});
        if(!response.ok)throw new Error(`HTTP ${response.status}`);
        const data=await response.json();
        if(!Array.isArray(data.packets))throw new Error('Invalid packet-feed response');
        recordApiHealth(source,true,Date.now()-startedAt);
        result={source,packets:data.packets};break;
      } catch(error) { lastError=error; recordApiHealth(source,false,Date.now()-startedAt); }
    }
    if(!result)throw new Error(`All configured APIs are unavailable${lastError?.message?`: ${lastError.message}`:''}`);
    activeApiSource=result.source;
    updateActiveApiLabel();
    liveState.packets = result.packets.sort((a,b)=>new Date(b.timestamp||b.first_seen)-new Date(a.timestamp||a.first_seen));
    recordTrackedPacketCounters(liveState.packets);
    updateMyLog(liveState.packets);
    mapIngest();
    appStatsAccept(liveState.packets);
    appStatsSwitchBroker();
    channelsDecryptLive(liveState.packets);
    channelStatsRefresh();
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
    button.title = liveState.loading ? 'Refreshingâ€¦' : 'Refresh packets now';
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

// ---------- ZamkniÄ™cie aplikacji (odpowiednik Close application z Androida) ----------
let appClosed=false;
function closeApplication() {
  appClosed=true;
  document.getElementById('intro')?.remove();
  const overlay=document.createElement('div');
  overlay.id='app-closed';
  overlay.innerHTML=`<img src="assets/m2-logo.svg" alt="MÂ˛"><h2>MÂ˛ closed</h2><p>Background listening stopped.</p><button type="button" id="app-closed-reopen">Open again</button>`;
  document.body.appendChild(overlay);
  overlay.querySelector('#app-closed-reopen').addEventListener('click',()=>location.reload());
}
let settingsApiLogOpen=false;
function renderApiLogDialog() {
  const entries=apiHealthLog[sourceLabel(activeApiSource)]||[];
  const rows=entries.map(entry=>`<div class="api-log-row ${entry.status==='ONLINE'?'online':'offline'}"><b>${entry.status}</b><span>${escapeHtml(new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(entry.start))} â€“ ${escapeHtml(new Intl.DateTimeFormat('pl-PL',{timeZone:'Europe/Warsaw',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(entry.last))}</span><span>${Number(entry.response)||0} ms Â· ${Number(entry.checks||1)} checks</span></div>`).join('');
  return `<div class="dialog-backdrop" id="api-log-backdrop"><section class="dialog" role="dialog" aria-modal="true" aria-label="API log"><h3>API log Â· ${escapeHtml(sourceLabel(activeApiSource))}</h3><div class="api-log-list">${rows||'<div class="empty-feed">No checks recorded yet.</div>'}</div><div class="dialog-actions"><button type="button" class="danger-link" id="api-log-reset">Reset</button><button type="button" class="dialog-cancel" id="api-log-close">Close</button></div></section></div>`;
}
function renderSettings() {
  screen.innerHTML = `<section class="settings-screen"><div class="eyebrow">PERSONALIZE MÂ˛</div><h1>Settings</h1><section class="api-settings"><div class="settings-heading"><h2>Packet APIs</h2><button type="button" id="open-api-log">Log</button></div><p class="settings-intro">The app tries these APIs in order. If the first one is unavailable, it switches automatically to the next working source.</p><div class="api-source-list">${apiSources.map((source,index)=>`<div class="api-source-row"><span class="api-order">${index+1}</span><code>${escapeHtml(source)}</code>${source===activeApiSource?'<b class="api-active-badge">ACTIVE</b>':''}<button type="button" data-primary-api="${index}" ${index===0?'disabled':''}>Make primary</button>${apiSources.length>1?`<button type="button" data-remove-api="${index}" aria-label="Remove API ${escapeHtml(source)}">Remove</button>`:''}</div>`).join('')}</div><div class="api-add-form"><label for="api-source-input">Add API base URL</label><div><input id="api-source-input" type="url" autocomplete="url" placeholder="https://api.example.org"><button id="add-api-source" type="button">Add API</button></div><p id="api-source-error" class="form-error" role="status" aria-live="polite"></p></div></section><section class="refresh-settings"><h2>Live refresh interval</h2><p class="settings-intro">Choose how often the packet feed is checked. The countdown next to LIVE follows this interval.</p><label for="refresh-interval">Refresh every</label><select id="refresh-interval">${REFRESH_OPTIONS.map(value=>`<option value="${value}" ${value===refreshIntervalMs?'selected':''}>${formatRefreshInterval(value)}</option>`).join('')}</select></section><section class="tracked-settings"><h2>Tracked keys</h2><p class="settings-intro">Add a full public key to recognize it in packet sources, observers and recorded routes.</p><div class="key-form"><label>Public key Â· 64 hex characters<input id="tracked-key" autocomplete="off" spellcheck="false" placeholder="Paste the full public key" maxlength="64"></label><button class="add-key-button" id="add-tracked-key" type="button">Add key</button><div id="key-form-error" class="form-error" role="status" aria-live="polite"></div></div><div class="key-storage-note"><span>SESSION ONLY</span> Keys and names are kept only for this browser session. Packet counts below use the loaded feed (${liveState.packets.length} of 250 packets).</div><div class="tracked-key-list"><div class="keys-heading"><strong>Saved keys</strong><span>${trackedKeys.length}</span></div>${trackedKeys.length?trackedKeys.map((item,index)=>`<div class="tracked-key-row"><div><strong>${escapeHtml(item.name||'Name unavailable')}</strong><code>${escapeHtml(item.key)}</code><small class="tracked-packet-count">${packetCountForTrackedKey(item.key)} matching packets in loaded feed</small></div><button type="button" data-remove-key="${index}" aria-label="Remove ${escapeHtml(item.name||'key')}">Remove</button></div>`).join(''):'<div class="empty-keys">No tracked keys yet.</div>'}</div></section><section class="about-settings"><h2>About MÂ˛</h2><p class="settings-intro">Exports (my log, maps) are saved to your browser's download folder. Channel keys never leave this browser.</p><a class="settings-link" href="https://ko-fi.com/beepoo304" target="_blank" rel="noopener noreferrer">Support MÂ˛ on Ko-fi â€” ko-fi.com/beepoo304</a><a class="settings-link" href="https://github.com/beepoo304/M2_WEB" target="_blank" rel="noopener noreferrer">Open source on GitHub â€” github.com/beepoo304/M2_WEB</a><p class="version-note">MÂ˛ Web version 0.3.0</p><button type="button" id="close-application" class="danger-button">Close application</button><p class="settings-intro">Stops background listening and closes MÂ˛.</p></section></section>${settingsApiLogOpen?renderApiLogDialog():''}`;
  screen.querySelector('.key-storage-note').lastChild.textContent=' Keys, start dates and packet counters are kept only for this browser session.';
  screen.querySelectorAll('.tracked-packet-count').forEach((element,index)=>{
    const item=trackedKeys[index];
    element.textContent=`START ${formatCounterStart(item.counterStartedAt)} Â· PACKETS ${Number(item.packetCount||0).toLocaleString('en-US')}`;
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
    addButton.disabled=true;addButton.textContent='Importing nameâ€¦';error.textContent='Looking up this key in the MeshCore node directoryâ€¦';
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
  const rows=myLogPackets.map(packet=>`<button class="packet-row packet-own" data-my-log-id="${escapeHtml(packet.id)}" type="button"><span class="packet-time"><b>${packetTime(packet)}</b><small class="packet-age">${relativeAge(packet)}</small></span><span class="packet-type type-${Number(packet.payload_type)}">${escapeHtml(packetType(packet))}<small>${escapeHtml((packet.direction||'rx').toUpperCase())}</small></span><span class="packet-copy"><strong>${liveIdentityMarkup(packet)}</strong><span>${renderTrackedText(packetSummary(packet))}</span><small>${escapeHtml(packet.observer_iata||'Observer')} Â· ${Number(packet.observation_count||1)} observation${Number(packet.observation_count||1)===1?'':'s'}</small></span><span class="packet-route">${escapeHtml(pathSummary(packet))}<small>${packet.rssi==null?'':`${escapeHtml(packet.rssi)} dBm`}</small></span></button>`).join('');
  screen.innerHTML=`<section class="live-screen my-log-screen"><div class="live-heading"><div><div class="eyebrow">SAVED DEVICE ACTIVITY</div><h1>My devices log</h1><p>Newest first Â· ${myLogPackets.length} / 250</p></div><div class="my-log-actions"><button id="export-my-log" type="button" ${myLogPackets.length?'':'disabled'}>Export</button><button id="clear-my-log" type="button" ${myLogPackets.length?'':'disabled'}>Clear</button></div></div><div class="packet-list">${rows||'<div class="empty-feed">No activity from saved device keys.</div>'}</div></section>${liveState.selected?renderDetail(liveState.selected):''}`;
  screen.querySelectorAll('[data-my-log-id]').forEach(row=>row.addEventListener('click',()=>{liveState.selected=myLogPackets.find(packet=>String(packet.id)===row.dataset.myLogId)||null;liveState.details=null;liveState.detailsError='';liveState.showAllRoutes=false;loadPacketDetails(liveState.selected,renderMyLog);}));
  screen.querySelector('.detail-close')?.addEventListener('click',closeDetail);
  screen.querySelector('.detail-close-secondary')?.addEventListener('click',closeDetail);
  screen.querySelector('.route-toggle')?.addEventListener('click',()=>{liveState.showAllRoutes=!liveState.showAllRoutes;renderMyLog();});
  screen.querySelector('.packet-detail-backdrop')?.addEventListener('click',event=>{if(event.target===event.currentTarget)closeDetail();});
  screen.querySelector('.copy-packet-hash')?.addEventListener('click',event=>copyValue(liveState.selected?.hash,event.currentTarget));
  screen.querySelector('.copy-source-key')?.addEventListener('click',event=>{const decoded=parseDecoded(liveState.details?.packet||liveState.selected||{});copyValue(decoded.pubKey||decoded.publicKey||decoded.srcPubKey||decoded.srcKey,event.currentTarget);});
  document.getElementById('clear-my-log')?.addEventListener('click',()=>{myLogPackets=[];saveMyLogPackets();renderMyLog();});
  document.getElementById('export-my-log')?.addEventListener('click',()=>{const content=myLogPackets.map(packet=>`${packetTime(packet)} Â· ${packetType(packet)} Â· ${liveIdentityLabel(packet)}\n${packetSummary(packet)}\nHash: ${packet.hash||'â€”'}\n`).join('\n');const blob=new Blob([content],{type:'text/plain'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`M2_MY_LOG_${new Date().toISOString().replace(/[:.]/g,'-')}.txt`;link.click();URL.revokeObjectURL(url);});
}
// ---------- Ekran Channels: peĹ‚ny port z MÂ˛ Android (ChannelsScreen.kt) ----------
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
  const value=channelUiState.addMode==='private'?channelUiState.input.trim():`#${channelUiState.input.trim().replace(/^#/,'')}`;
  const parsed=await M2Channels.parseChannel(value);
  if(!parsed){ channelUiState.invalid=true; renderChannels(); return; }
  if(!savedChannels.some(item=>(item.secret||item.name)===value||item.name===parsed.name&&item.secret===parsed.secret)){
    savedChannels.unshift({ ...parsed, lastReadAt:0, clearedAt:0, messages:[], loading:false, error:'' });
    if(savedChannels.length>50)savedChannels.length=50;
    saveChannels();
  }
  channelUiState.add=false; channelUiState.addMode=null; channelUiState.namedPublic=false; channelUiState.input=''; channelUiState.invalid=false;
  channelStatsRefresh(); renderChannels();
}

function renderChannelMessageDetails() {
  if(!channelUiState.details)return '';
  const message=channelUiState.details, loading=channelUiState.detailsLoading;
  const route=loading?'<p class="details-loading">Loading message detailsâ€¦</p>'
    :`<dl class="details-list">
      <div><dt>Time</dt><dd>${escapeHtml(warsawDateTime(message.timestamp))}</dd></div>
      <div><dt>Hops</dt><dd>${Number(message.hops||0)}</dd></div>
      <div><dt>Route</dt><dd>${escapeHtml(message.route&&message.route.length?message.route.join(' â†’ '):'Unavailable')}</dd></div>
      <div><dt>Seen</dt><dd>${Number(message.repeats||1)} observations</dd></div>
      <div><dt>Observers</dt><dd>${escapeHtml((message.observers||[]).join(', ')||'Unavailable')}</dd></div>
      <div><dt>Signal</dt><dd>${message.rssi==null?'â€”':`${message.rssi} dBm`} Â· ${message.snr==null?'â€”':`${message.snr} dB`}</dd></div>
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
      <small>Sent ${values.filter(event=>event.sent).length} Â· Mentions ${values.filter(event=>event.mention).length}</small></div>`;
  }).join('');
  return `<section class="channels-screen"><div class="eyebrow">CHANNEL STATISTICS</div><h1>Channel statistics</h1>
    <label class="dialog-field"><span>Tracked key</span><select id="stats-key">${trackedKeys.map(item=>`<option value="${escapeHtml(item.key)}" ${item.key===selectedKey?'selected':''}>${escapeHtml(item.key.slice(0,4).toUpperCase())} Â· ${escapeHtml(item.name||'Unnamed')}</option>`).join('')||'<option value="">Add a tracked key first</option>'}</select></label>
    <div class="stats-totals"><div><b>${selectedEvents.filter(event=>event.sent).length}</b><span>Sent</span></div><div><b>${selectedEvents.filter(event=>event.mention).length}</b><span>Mentions</span></div><div><b>${grouped.size}</b><span>Channels</span></div></div>
    ${selectedEvents.length?`<button type="button" class="danger-link" id="stats-reset">Reset</button>`:''}
    <div class="stats-list">${rows||'<div class="empty-feed">No related channel traffic in the last 24 hours.</div>'}</div>
    <button type="button" class="back-link" id="stats-back">â† Channels</button></section>`;
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
    <button type="button" class="back-link" id="app-stats-back">â† Channels</button></section>`;
}

async function renderChannels() {
  if(channelUiState.appStatistics){ renderChannelsAppStats(); return; }
  if(channelUiState.statistics){ renderChannelsStats(); return; }
  const selected=liveState.selectedChannel;
  const channel=selected?channelByIdentity(selected):null;
  if(channel&&!channel.isPrivate&&!(Array.isArray(channel.messages)&&channel.messages.length)&&!channel.loading){ channelsLoadRemote(channel); return; }
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
      <button class="channel-open" type="button"><b>${escapeHtml(item.name)}${item.isPrivate?' đź”‘':''}</b><span>${escapeHtml(String(item.hash||'').slice(0,2))} Â· ${item.loading?'Loadingâ€¦':item.error?'Error':`${(item.messages||[]).length} messages`}</span></button>
      ${trackedUnread?`<b class="unread-badge tracked">${trackedUnread}</b>`:''}${otherUnread?`<b class="unread-badge">${otherUnread}</b>`:''}
      ${item.isPrivate?`<button type="button" data-rename-channel="${escapeHtml(item.name)}" title="Rename channel">âśŽ</button>`:''}
      <button type="button" data-remove-channel="${escapeHtml(item.name)}" title="Remove channel">đź—‘</button>
    </div>`;
  }).join('');
  const messages=channel?.messages||[];
  const messageList=channel?(channel.loading?'<div class="empty-feed">Loading messagesâ€¦</div>':channel.error?`<div class="feed-error"><strong>Channel unavailable</strong><span>${escapeHtml(channel.error)}</span></div>`:messages.map(message=>{
    const tracked=messageIsTracked(message);
    return `<article class="channel-message ${tracked?'tracked':''}" data-message-id="${escapeHtml(message.id)}"><b>${renderTrackedText(message.sender)}</b><small>${escapeHtml(warsawDateTime(message.timestamp))} Â· ${Number(message.hops||0)} hops</small><p>${renderTrackedText(message.text||'')}</p></article>`;
  }).join('')||'<div class="empty-feed">No messages received.</div>'):'';
  screen.innerHTML=`<section class="channels-screen"><div class="eyebrow">SAVED CHANNELS</div><h1>${channel?escapeHtml(channel.name):'Channels'}</h1>
    ${channel?`<div class="channel-view-head"><button id="back-channels" type="button">â† All channels</button><div><button type="button" id="channel-refresh">â†» Refresh</button><button type="button" id="channel-clear" ${messages.length?'':'disabled'}>Delete all</button></div><span>${messages.length} messages</span></div><div class="channel-messages">${messageList}</div>`
    :`<button type="button" class="add-channel-tile" id="open-add-channel">ďĽ‹ Add channel</button>
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
  const descriptions = {'My log':'A focused log of packets related to the public keys you save in Settings.','Channels':'Public and locally decrypted private channels, with the MÂ˛ channel tools.','Map':'Tracked packet routes, repeaters, distances and the longest-route flight.','Settings':'Saved devices, API selection, refresh behaviour and web-session key controls.','Guide':'Packet types, route colours, map modes and network-data notes.'};
  screen.innerHTML = `<section class="welcome-panel"><div class="eyebrow">${escapeHtml(name.toUpperCase())}</div><h1>${escapeHtml(name)}</h1><p>${escapeHtml(descriptions[name])}</p></section>`;
}
function currentScreen() { return document.querySelector('.nav-item.active')?.dataset.screen || 'Live'; }
function renderScreen(name) { if(name==='Live')renderLive();else if(name==='My log')renderMyLog();else if(name==='Channels')renderChannels();else if(name==='Map')renderMap();else if(name==='Settings')renderSettings();else if(name==='Guide')renderGuide();else renderPlaceholder(name); }
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
  if(appClosed) return;
  if(document.hidden || document.querySelector('.nav-item.active')?.dataset.screen!=='Live') return;
    if(Date.now() >= nextRefreshAt && !liveState.loading) loadPackets(false);
  updateRefreshCountdown();
}, 50);
setInterval(() => { if(!document.hidden && document.querySelector('.nav-item.active')?.dataset.screen==='Live') document.querySelectorAll('.packet-row').forEach(row=>{const item=liveState.packets.find(packet=>String(packet.id)===row.dataset.packetId);const age=row.querySelector('.packet-age');if(item&&age)age.textContent=relativeAge(item);}); }, 1000);
document.addEventListener('visibilitychange', () => { if(!document.hidden && document.querySelector('.nav-item.active')?.dataset.screen==='Live') loadPackets(); });

// MÂ˛ intro: a short local signal-flight animation, independent of network status.
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
