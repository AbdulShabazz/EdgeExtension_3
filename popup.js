
const $ = sel => document.querySelector(sel);
const log = (s) => { $('#log').textContent += s + '\n'; $('#log').scrollTop = 1e9; };

$('#btnOptions').onclick = () => chrome.runtime.openOptionsPage();

$('#btnLogin').onclick = async () => {
  const resp = await chrome.runtime.sendMessage({ type: 'login' });
  if (resp?.ok) log('SUCCESS! - Authenticated.');
  else log('ERROR! - Auth failed: ' + (resp?.error || 'unknown'));
};

$('#btnShowRedirect').onclick = async () => {
  const resp = await chrome.runtime.sendMessage({ type: 'getRedirectUri' });
  if (resp?.redirectUri) {
    $('#redirect').textContent = `Authorized redirect URI: ${resp.redirectUri}`;
    log('Copy this URI into Google Cloud OAuth 2.0 Client → Authorized redirect URIs.');
  }
};

$('#btnRun').onclick = async () => {
  const title = $('#title').value.trim();
  const privacy = $('#privacy').value;
  const delayMs = parseInt($('#delay').value || '0', 10);

  log('Starting… fetching uploads & destination…');
  const resp = await chrome.runtime.sendMessage({ type: 'run', options: { title, privacy, delayMs } });
  if (!resp?.ok) { log('ERROR! - Error: ' + (resp?.error || 'unknown')); return; }
  const { inserted, skipped, errors, total } = resp.result;
  log(`Done. Total uploads: ${total}. Inserted: ${inserted}. Skipped: ${skipped}. Errors: ${errors}.`);
};

// progress updates during run
chrome.runtime.onMessage.addListener((m) => {
  if (m?.type === 'progress') {
    const { inserted, skipped, errors, total, msg } = m.data;
    //log(`Progress: inserted=${inserted}, skipped=${skipped}, errors=${errors}, total=${total}`);
    inserted_.textContent = inserted;
    skipped_.textContent = skipped;
    errors_.textContent = errors;
    total_.textContent = total;
    log(msg);
  }
});