// M² ExportLocationStore: własny folder eksportu (File System Access API), domyślnie Pobrane przeglądarki.
// Uchwyt folderu trzymany w IndexedDB; bez wsparcia API lub bez zgody — zwykłe pobieranie.
const M2Export = (() => {
  const DB = 'm2-export', STORE = 'kv', KEY = 'dir';
  let dir = null;
  const supported = typeof window.showDirectoryPicker === 'function';
  function db() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
    });
  }
  async function idb(mode, fn) {
    const d = await db();
    return new Promise((resolve, reject) => {
      const tx = d.transaction(STORE, mode), req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req?.result); tx.onerror = () => reject(tx.error);
    });
  }
  const ready = (async () => { try { if (supported) dir = (await idb('readonly', s => s.get(KEY))) || null; } catch { dir = null; } })();
  function label(handle = dir) { return handle ? handle.name : 'Downloads'; }
  async function choose() { return window.showDirectoryPicker({ id: 'm2-export', mode: 'readwrite' }); }
  async function save(handle) {
    dir = handle || null;
    try { await idb('readwrite', s => dir ? s.put(dir, KEY) : s.delete(KEY)); } catch {}
  }
  function download(name, blob) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob); link.download = name;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 60000);
  }
  // Zapis pliku; zwraca etykietę miejsca, w którym faktycznie wylądował.
  async function write(name, blob) {
    await ready;
    if (dir) {
      try {
        let perm = await dir.queryPermission({ mode: 'readwrite' });
        if (perm !== 'granted') perm = await dir.requestPermission({ mode: 'readwrite' });
        if (perm === 'granted') {
          const file = await dir.getFileHandle(name, { create: true }), out = await file.createWritable();
          await out.write(blob); await out.close();
          return dir.name;
        }
      } catch {}
    }
    download(name, blob);
    return 'Downloads';
  }
  return { supported, ready, label, choose, save, write, get dir() { return dir; } };
})();
