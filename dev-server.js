const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const root = __dirname;
const port = Number(process.env.PORT || 4173);
const mime = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png' };

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  if (url.pathname === '/api.php') {
    const resource=url.searchParams.get('resource'); let upstreamUrl;
    const source=url.searchParams.get('source')||'https://live.meshcorekk.xyz';
    let parsedSource;
    try { parsedSource=new URL(source); } catch {}
    const host=parsedSource?.hostname?.toLowerCase()||'';
    const publicHost=host.includes('.')&&!/^(localhost|.*\.(local|internal|test|lan))$/.test(host)&&!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)&&!host.includes(':');
    if(!parsedSource||parsedSource.protocol!=='https:'||!publicHost||parsedSource.username||parsedSource.password||parsedSource.search||parsedSource.hash){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'API source must be a public HTTPS base URL'}));return;}
    const base=source.replace(/\/$/,'');
    if(resource==='packets') { const limit=Math.max(1,Math.min(250,Number.parseInt(url.searchParams.get('limit')||'250',10)||250)); upstreamUrl=`${base}/api/packets?limit=${limit}`; }
    else if(resource==='packet') { const id=url.searchParams.get('id')||''; if(!/^\d{1,20}$/.test(id)){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'Invalid packet id'}));return;} upstreamUrl=`${base}/api/packets/${id}`; }
    else if(resource==='directory') { upstreamUrl=`${base}/api/nodes?limit=3000`; }
    else if(resource==='channel') { const name=(url.searchParams.get('name')||'').trim(); if(!name||name.length>128||/[\u0000-\u001f]/.test(name)){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'Invalid channel name'}));return;} upstreamUrl=`${base}/api/channels/${encodeURIComponent(name)}/messages?limit=250`; }
    else if(resource==='node') { const key=(url.searchParams.get('id')||'').toLowerCase(); if(!/^[a-f0-9]{64}$/.test(key)){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'A full 64-character public key is required'}));return;} upstreamUrl=`${base}/api/nodes?limit=3000`; }
    else if(resource==='neighbours') {
      const key=(url.searchParams.get('id')||'').toLowerCase();
      if(!/^[a-f0-9]{64}$/.test(key)){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'A full 64-character public key is required'}));return;}
      try {
        const [detailResponse,healthResponse,nodesResponse]=await Promise.all([
          fetch(`${base}/api/nodes/${key}`,{signal:AbortSignal.timeout(12000),headers:{accept:'application/json'}}),
          fetch(`${base}/api/nodes/${key}/health`,{signal:AbortSignal.timeout(12000),headers:{accept:'application/json'}}),
          fetch(`${base}/api/nodes?limit=3000`,{signal:AbortSignal.timeout(12000),headers:{accept:'application/json'}})
        ]);
        if(!detailResponse.ok||!nodesResponse.ok)throw new Error(`API returned HTTP ${!detailResponse.ok?detailResponse.status:nodesResponse.status}`);
        const detail=await detailResponse.json(); const health=healthResponse.ok?await healthResponse.json():{}; const directory=await nodesResponse.json();
        const names=new Map();
        (Array.isArray(directory.nodes)?directory.nodes:[]).forEach(node=>{const nodeKey=String(node.public_key||'').toLowerCase();if(/^[a-f0-9]{64}$/.test(nodeKey)){const prefix=nodeKey.slice(0,4).toUpperCase();const values=names.get(prefix)||[];values.push({key:nodeKey,name:String(node.name||'Unknown RPT')});names.set(prefix,values);}});
        const counts=new Map();
        (Array.isArray(detail.recentAdverts)?detail.recentAdverts:[]).forEach(advert=>(Array.isArray(advert.observations)?advert.observations:[]).forEach(observation=>{try{const path=JSON.parse(observation.path_json||'[]');const first=String(path[0]||'').trim().toUpperCase();if(/^[A-F0-9]{4,}$/.test(first))counts.set(first.slice(0,4),(counts.get(first.slice(0,4))||0)+1);}catch{}}));
        const neighbours=[...counts].map(([hash,count])=>{const candidates=names.get(hash)||[];return {hash,name:candidates.length===1?candidates[0].name:candidates.length?'Ambiguous RPT':'Unknown RPT',count};}).sort((a,b)=>b.count-a.count);
        res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify({node:detail.node||{},stats:health.stats||detail.stats||{},neighbours}));
      } catch(error) {res.writeHead(502,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:error.message||'Could not load RPT information'}));}
      return;
    }
    else { res.writeHead(400, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unsupported resource'})); return; }
    try {
      const upstream = await fetch(upstreamUrl, { signal:AbortSignal.timeout(12000), headers:{ accept:'application/json', 'cache-control':'no-cache' } });
      const body=await upstream.text();
      if(resource==='node'&&upstream.ok) {
        let data;try{data=JSON.parse(body);}catch{data={};}
        const key=(url.searchParams.get('id')||'').toLowerCase();
        const node=(Array.isArray(data.nodes)?data.nodes:[]).find(item=>String(item.public_key||'').toLowerCase()===key);
        if(!node||!String(node.name||'').trim()){res.writeHead(404,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify({error:'Public key not found with an advertised name in the MeshCore node directory'}));return;}
        res.writeHead(200, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
        res.end(JSON.stringify({key:String(node.public_key).toUpperCase(),name:String(node.name).trim()}));return;
      }
      res.writeHead(upstream.status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
      res.end(body);
    } catch (error) { res.writeHead(502, {'Content-Type':'application/json','Cache-Control':'no-store'}); res.end(JSON.stringify({error:error.message || 'Upstream packet feed unavailable'})); }
    return;
  }
  let file = path.resolve(root, `.${decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)}`);
  if (!file.startsWith(root + path.sep) && file !== path.join(root,'index.html')) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(file, (error, data) => {
    if (error) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, {'Content-Type':mime[path.extname(file)] || 'application/octet-stream','Cache-Control':'no-store'}); res.end(data);
  });
}).listen(port, '127.0.0.1', () => console.log(`M² Web preview: http://127.0.0.1:${port}`));
