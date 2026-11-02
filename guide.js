// M² Web — ekran Guide (przewodnik w 7 językach, treść z M² Android).
const GUIDE_LANG_STORAGE = 'm2-web-guide-language-v1';
const GUIDE_LANGS = ['PL', 'EN', 'RU', 'SK', 'CZ', 'DE', 'FR'];
const GUIDE_COLORS = { green: '#42d47b', orange: '#f0a84b', blue: '#2196f3', purple: '#ab47bc', red: '#ff6565' };

function guideLanguage() {
  try { const saved = localStorage.getItem(GUIDE_LANG_STORAGE); if (GUIDE_LANGS.includes(saved)) return saved; } catch {}
  return 'PL';
}

function guideRow(label, description, color) {
  return `<div class="guide-row"><div class="guide-label" style="color:${color || 'inherit'}">${escapeHtml(label)}</div>${description ? `<div class="guide-desc">${escapeHtml(description)}</div>` : ''}</div>`;
}
function guideSection(title, rows) {
  return `<section class="guide-section"><h2>${escapeHtml(title)}</h2>${rows}</section>`;
}

function renderGuide() {
  const lang = guideLanguage(), w = GUIDE_TRANSLATIONS[lang], c = GUIDE_COLORS;
  const modes = ['Starts at key', 'Last recorded hop', 'Related to key', 'Reported by key', 'All for selected key'];
  const notes = Array.from({ length: 9 }, (_, i) => `<p class="guide-note">${i + 1}. ${escapeHtml(w[28 + i])}</p>`).join('') + `<p class="guide-note">10. ${escapeHtml(w[37])}</p>`;
  screen.innerHTML = `<section class="guide-screen">
    <div class="guide-head"><h1>${escapeHtml(w[0])}</h1>
      <label class="guide-lang"><span class="sr-only">Language</span><select id="guide-language" aria-label="Language">${GUIDE_LANGS.map(code => `<option value="${code}" ${code === lang ? 'selected' : ''}>${code === 'SK' ? 'SLO · Slovenčina' : code}</option>`).join('')}</select></label></div>
    ${guideSection(w[1], guideRow('—', w[2], c.green) + guideRow('—', w[3], c.orange) + guideRow('—', w[4], c.blue) + guideRow('0652', w[5], c.purple) + guideRow('XXX km', w[6], c.red))}
    ${guideSection(w[8], guideRow('SOURCE', w[9], c.green) + guideRow('LAST RECORDED HOP', w[10], c.green) + guideRow('IN ROUTE', w[11], c.green) + guideRow('REPORTED BY', w[12], c.green) + guideRow('REPLY TO', w[13], c.orange) + guideRow('NO ROUTE', w[7], c.red) + guideRow('NO GPS FOR 0652', w[5], c.purple) + guideRow('REPEATER / COMPANION / ROOM SERVER / SENSOR', '', null))}
    ${guideSection(w[19], modes.map((label, i) => guideRow(label, w[20 + i], c.green)).join(''))}
    ${guideSection(w[14], guideRow('Packets · Routes', w[15], c.green) + guideRow('Distance', w[16], c.green) + guideRow('MAX HOPS', w[17], c.green) + guideRow('NO GPS RPT', w[18], c.purple) + guideRow(w[25], w[26], c.orange) + guideRow('Longest route', w[4], c.blue))}
    ${guideSection(w[27], notes + `<a class="guide-link" href="https://www.instagram.com/m2.meshcore.app/" target="_blank" rel="noopener noreferrer">@m2.meshcore.app</a>`)}
  </section>`;
  document.getElementById('guide-language').addEventListener('change', event => {
    try { localStorage.setItem(GUIDE_LANG_STORAGE, event.target.value); } catch {}
    renderGuide();
  });
}
