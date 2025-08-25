## Add videos to playlist

Below is a complete **Microsoft Edge (Manifest V3)** extension that signs you in with Google via `chrome.identity.launchWebAuthFlow`, discovers your channel’s **Uploads** playlist, optionally **creates/reuses** a destination playlist, then **adds every uploaded video** to that destination—handling pagination and skipping duplicates. (Auth + redirect URI pattern, Edge API support, and YouTube API method/quotas are documented in the citations.) ([Chrome for Developers][1], [Microsoft Learn][2], [Google for Developers][3])

---

### Project layout (Manifest V3)

* `manifest.json` — MV3 manifest; uses **identity** + **storage** permissions and fetches Google/YouTube endpoints over HTTPS. ([Chrome for Developers][1])
* `background.js` — service worker; performs **OAuth 2.0 (PKCE)** with `launchWebAuthFlow`, stores tokens, calls YouTube Data API to list/create/insert playlist items with pagination and dedupe logic. ([Chrome for Developers][1], [Google for Developers][4])
* `popup.html` / `popup.js` — minimal UI to authenticate, choose **destination title** and **privacy**, then run the bulk add.
* `options.html` / `options.js` — lets you paste your **Google OAuth Client ID** and shows the **authorized redirect URI** (computed via `chrome.identity.getRedirectURL`). Register this exact URI in Google Cloud. ([Chrome for Developers][1])

---

### Files

#### 1) `manifest.json`

```json
{
  "manifest_version": 3,
  "name": "YouTube: Add All Uploads to a Playlist (Edge)",
  "version": "1.0.0",
  "description": "Bulk-add every uploaded video from your channel to a chosen playlist (creates if missing).",
  "permissions": ["identity", "storage"],
  "host_permissions": [
    "https://accounts.google.com/*",
    "https://oauth2.googleapis.com/*",
    "https://www.googleapis.com/*"
  ],
  "background": { "service_worker": "background.js", "type": "module" },
  "action": { "default_popup": "popup.html" },
  "options_page": "options.html"
}
```

#### 2) `background.js`

```js
// MV3 service worker (Edge/Chrome). Requires a Web Application OAuth2 Client ID.
// Stores tokens in chrome.storage.local. Uses PKCE + launchWebAuthFlow.
// YouTube scopes: https://www.googleapis.com/auth/youtube or /auth/youtube.force-ssl

const API_BASE = 'https://www.googleapis.com/youtube/v3';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth';
const SCOPES = [
  'https://www.googleapis.com/auth/youtube.force-ssl'
];

const STORE_KEYS = {
  CLIENT_ID: 'google_oauth_client_id',
  TOKENS: 'oauth_tokens' // { access_token, refresh_token, expires_at }
};

// ---------- Utility: storage ----------
async function getStore(key) {
  return (await chrome.storage.local.get([key]))[key];
}
async function setStore(key, val) {
  await chrome.storage.local.set({[key]: val});
}

// ---------- Utility: PKCE helpers ----------
function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function sha256(str) {
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}
function randomString(len = 64) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random()*chars.length)];
  return s;
}

// ---------- OAuth: get valid access token ----------
async function getValidAccessToken(interactive = true) {
  const clientId = await getStore(STORE_KEYS.CLIENT_ID);
  if (!clientId) throw new Error('Missing Google OAuth Client ID. Open Options and set it.');

  let tokens = await getStore(STORE_KEYS.TOKENS);
  const now = Math.floor(Date.now() / 1000);

  // Refresh path (if we have refresh_token and expired)
  if (tokens?.access_token && tokens?.expires_at && tokens.expires_at - 60 > now) {
    return tokens.access_token;
  }
  if (tokens?.refresh_token) {
    try {
      const refreshed = await tokenRequest({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: tokens.refresh_token
      });
      tokens.access_token = refreshed.access_token;
      tokens.expires_at = now + (refreshed.expires_in || 3600);
      await setStore(STORE_KEYS.TOKENS, tokens);
      return tokens.access_token;
    } catch (e) {
      // fall through to full auth
      console.warn('Refresh failed, falling back to full auth', e);
    }
  }

  if (!interactive) throw new Error('No valid access token and interactive=false.');

  // Full auth with PKCE
  const codeVerifier = randomString(64);
  const codeChallenge = base64url(await sha256(codeVerifier));
  const redirectUri = chrome.identity.getRedirectURL('oauth2'); // https://<ext-id>.chromiumapp.org/oauth2
  const authParams = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: SCOPES.join(' '),
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });
  const authUrl = `${AUTH_URL}?${authParams.toString()}`;

  const redirect = await chrome.identity.launchWebAuthFlow({
    url: authUrl,
    interactive: true
  });

  const redirected = new URL(redirect);
  const authCode = redirected.searchParams.get('code');
  if (!authCode) throw new Error('Authorization code not returned.');

  const tokenResp = await tokenRequest({
    grant_type: 'authorization_code',
    code: authCode,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });

  const newTokens = {
    access_token: tokenResp.access_token,
    refresh_token: tokenResp.refresh_token, // may be undefined unless Google issues one
    expires_at: Math.floor(Date.now() / 1000) + (tokenResp.expires_in || 3600)
  };
  await setStore(STORE_KEYS.TOKENS, newTokens);
  return newTokens.access_token;
}

async function tokenRequest(body) {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(body).toString()
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Token endpoint error: ${res.status} ${t}`);
  }
  return res.json();
}

// ---------- YouTube API helpers ----------
async function ytFetch(path, params = {}, init = {}) {
  const token = await getValidAccessToken(true);
  const url = new URL(API_BASE + path);
  Object.entries(params).forEach(([k,v]) => {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  });
  const res = await fetch(url.toString(), {
    ...init,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/json',
      ...(init.headers || {})
    }
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`YouTube API ${path} failed: ${res.status} ${t}`);
  }
  return res.json();
}

async function getUploadsPlaylistId() {
  const data = await ytFetch('/channels', { part: 'contentDetails', mine: 'true', maxResults: 1 });
  const items = data.items || [];
  if (!items.length) throw new Error('No channel found for this Google account.');
  return items[0].contentDetails.relatedPlaylists.uploads;
}

async function listAllVideoIdsInPlaylist(playlistId) {
  let pageToken;
  const ids = [];
  do {
    const data = await ytFetch('/playlistItems', {
      part: 'contentDetails',
      playlistId,
      maxResults: 50,
      pageToken
    });
    (data.items || []).forEach(it => {
      const vid = it?.contentDetails?.videoId;
      if (vid) ids.push(vid);
    });
    pageToken = data.nextPageToken;
  } while (pageToken);
  return ids;
}

async function findOrCreateDestinationPlaylist(title, privacyStatus = 'unlisted') {
  // search existing
  let pageToken, foundId = null;
  do {
    const data = await ytFetch('/playlists', { part: 'snippet', mine: 'true', maxResults: 50, pageToken });
    const hit = (data.items || []).find(p => (p.snippet?.title || '').toLowerCase() === title.toLowerCase());
    if (hit) { foundId = hit.id; break; }
    pageToken = data.nextPageToken;
  } while (pageToken);

  if (foundId) return foundId;

  // create one
  const create = await ytFetch('/playlists', { part: 'snippet,status' }, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      snippet: { title },
      status: { privacyStatus }
    })
  });
  return create.id;
}

async function addVideoToPlaylist(playlistId, videoId, position = null) {
  const body = {
    snippet: {
      playlistId,
      resourceId: { kind: 'youtube#video', videoId }
    }
  };
  if (Number.isInteger(position)) body.snippet.position = position;

  const data = await ytFetch('/playlistItems', { part: 'snippet' }, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return data.id;
}

// ---------- Bulk add flow ----------
async function runBulkAdd({title, privacy, delayMs}) {
  const uploadsId = await getUploadsPlaylistId();
  const destId = await findOrCreateDestinationPlaylist(title, privacy);

  const [uploadIds, destIds] = await Promise.all([
    listAllVideoIdsInPlaylist(uploadsId),
    listAllVideoIdsInPlaylist(destId)
  ]);
  const have = new Set(destIds);

  let inserted = 0, skipped = 0, errors = 0;
  for (const vid of uploadIds) {
    if (have.has(vid)) { skipped++; continue; }
    try {
      await addVideoToPlaylist(destId, vid);
      inserted++;
      await new Promise(r => setTimeout(r, delayMs));
    } catch (e) {
      errors++;
      console.error('Insert failed for', vid, e);
    }
    // progress ping to popup
    chrome.runtime.sendMessage({
      type: 'progress',
      data: { inserted, skipped, errors, total: uploadIds.length }
    }).catch(()=>{ /* popup may be closed */ });
  }
  return { inserted, skipped, errors, total: uploadIds.length };
}

// ---------- Message handling from popup ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === 'getRedirectUri') {
      // show the exact value to register in Google Cloud
      sendResponse({ redirectUri: chrome.identity.getRedirectURL('oauth2') });
      return;
    }
    if (msg?.type === 'setClientId') {
      await setStore(STORE_KEYS.CLIENT_ID, msg.clientId.trim());
      sendResponse({ ok: true });
      return;
    }
    if (msg?.type === 'login') {
      try {
        const token = await getValidAccessToken(true);
        sendResponse({ ok: true, tokenPresent: !!token });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
      return;
    }
    if (msg?.type === 'run') {
      try {
        const result = await runBulkAdd(msg.options);
        sendResponse({ ok: true, result });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
      return;
    }
  })();
  return true; // keep the message channel alive for async
});
```

#### 3) `popup.html`

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>YT Bulk Add</title>
    <style>
      body { font: 13px/1.4 system-ui, Segoe UI, Arial, sans-serif; width: 360px; padding: 12px; }
      label { display:block; margin-top:8px; font-weight:600; }
      input, select, button { width:100%; box-sizing:border-box; margin-top:4px; padding:6px; }
      #log { margin-top:10px; height:120px; overflow:auto; background:#f6f6f6; padding:8px; border:1px solid #ddd; white-space:pre-wrap; }
      .row { display:flex; gap:8px; }
      .row > * { flex:1; }
      small.mono { font-family: ui-monospace, Menlo, Consolas, monospace; }
    </style>
  </head>
  <body>
    <div>
      <div class="row">
        <button id="btnLogin">Authenticate Google</button>
        <button id="btnOptions">Options</button>
      </div>

      <label>Destination playlist title</label>
      <input id="title" value="All My Uploads (Mirror)">

      <label>Privacy</label>
      <select id="privacy">
        <option value="unlisted" selected>unlisted</option>
        <option value="public">public</option>
        <option value="private">private</option>
      </select>

      <label>Insert pacing (ms between inserts)</label>
      <input id="delay" type="number" min="0" value="200">

      <div class="row" style="margin-top:10px;">
        <button id="btnRun">Add all uploads → playlist</button>
        <button id="btnShowRedirect">Show Redirect URI</button>
      </div>

      <div id="log"></div>
      <small class="mono" id="redirect"></small>
    </div>
    <script src="popup.js"></script>
  </body>
</html>
```

#### 4) `popup.js`

```js
const $ = sel => document.querySelector(sel);
const log = (s) => { $('#log').textContent += s + '\n'; $('#log').scrollTop = 1e9; };

$('#btnOptions').onclick = () => chrome.runtime.openOptionsPage();

$('#btnLogin').onclick = async () => {
  const resp = await chrome.runtime.sendMessage({ type: 'login' });
  if (resp?.ok) log('✅ Authenticated.');
  else log('❌ Auth failed: ' + (resp?.error || 'unknown'));
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
  if (!resp?.ok) { log('❌ Error: ' + (resp?.error || 'unknown')); return; }
  const { inserted, skipped, errors, total } = resp.result;
  log(`Done. Total uploads: ${total}. Inserted: ${inserted}. Skipped: ${skipped}. Errors: ${errors}.`);
};

// progress updates during run
chrome.runtime.onMessage.addListener((m) => {
  if (m?.type === 'progress') {
    const { inserted, skipped, errors, total } = m.data;
    log(`Progress: inserted=${inserted}, skipped=${skipped}, errors=${errors}, total=${total}`);
  }
});
```

#### 5) `options.html`

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>YT Bulk Add — Options</title>
    <style>
      body { font: 13px/1.4 system-ui, Segoe UI, Arial, sans-serif; max-width: 720px; padding: 20px; }
      label { display:block; margin-top:10px; font-weight:600; }
      input { width:100%; padding:6px; }
      code { background:#f6f6f6; padding:2px 4px; }
      .row { display:flex; gap:12px; align-items:flex-end; }
      .row > * { flex:1; }
      #status { margin-top:10px; }
    </style>
  </head>
  <body>
    <h2>Google OAuth Setup</h2>
    <p>1) Create an OAuth 2.0 <strong>Web application</strong> Client ID in Google Cloud.<br>
       2) Add this Authorized redirect URI: <code id="redir"></code><br>
       3) Paste your <strong>Client ID</strong> below and Save.</p>

    <div class="row">
      <div>
        <label>Google OAuth Client ID</label>
        <input id="clientId" placeholder="1234567890-abcdefg.apps.googleusercontent.com">
      </div>
      <button id="save">Save</button>
    </div>

    <div id="status"></div>
    <script src="options.js"></script>
  </body>
</html>
```

#### 6) `options.js`

```js
const $ = s => document.querySelector(s);

async function init() {
  const { redirectUri } = await chrome.runtime.sendMessage({ type: 'getRedirectUri' });
  $('#redir').textContent = redirectUri;

  const { google_oauth_client_id } = await chrome.storage.local.get(['google_oauth_client_id']);
  if (google_oauth_client_id) $('#clientId').value = google_oauth_client_id;
}
init();

$('#save').onclick = async () => {
  const clientId = $('#clientId').value.trim();
  if (!clientId) return ($('#status').textContent = 'Enter a Client ID.');
  const resp = await chrome.runtime.sendMessage({ type: 'setClientId', clientId });
  $('#status').textContent = resp?.ok ? 'Saved.' : 'Failed to save.';
};
```

---

### How to use (concise checklist)

* **Create OAuth client (Web application)** → in **Google Cloud Console → APIs & Services → Credentials**. Add **Authorized redirect URI** shown in **Options** (`https://<extension-id>.chromiumapp.org/oauth2` from `getRedirectURL('oauth2')`). This is required for `launchWebAuthFlow` in extensions. ([Chrome for Developers][1])
* **Scopes**: this extension uses `https://www.googleapis.com/auth/youtube.force-ssl` (write access). You may alternatively use `https://www.googleapis.com/auth/youtube` (broader). Both are listed among official YouTube scopes. ([Google for Developers][5])
* **Edge support**: Edge supports the `identity` API, with guidance to use `identity.launchWebAuthFlow`. Do **not** rely on `getAuthToken` in Edge. ([Microsoft Learn][2])
* **Redirect URI pattern**: Extensions must use `https://<extension-id>.chromiumapp.org/*` redirect URLs. The exact value is returned by `chrome.identity.getRedirectURL`. ([Chrome for Developers][1])
* **YouTube endpoints used**
  • `channels.list (mine=true, part=contentDetails)` → gives `relatedPlaylists.uploads` (your **Uploads** playlist). ([Google for Developers][3])
  • `playlistItems.list` → paginated fetch of video IDs (cost **1 unit**/page). ([Google for Developers][6])
  • `playlists.list` (search by title) + `playlists.insert` (create if missing). Each **list** costs **1 unit**; **insert** costs **50 units**. ([Google for Developers][7])
  • `playlistItems.insert` to add each video (cost **50 units** per call). Don’t try to insert into the *Uploads* playlist itself; API forbids that. ([Google for Developers][7])
* **Quotas**: Default project quota is **10,000 units/day**; resets at **midnight PT**. With `playlistItems.insert` at **50 units** each, 200 inserts ≈ **10,000 units** (plan batches). ([Google for Developers][7])

---

### Notes / design choices (quota-aware, deterministic)

* **Pagination**: The code follows `nextPageToken` for both source and destination playlists; each page costs 1 unit. ([Google for Developers][6])
* **Dedupe**: It preloads the destination playlist’s existing `videoId`s and skips matches to avoid wasted insert calls. (Inserts are the high-cost operation.) ([Google for Developers][7])
* **Pacing**: A small insert delay (default **200 ms**) reduces sporadic transient failures and keeps the service worker active; adjust in the popup. (General guidance: cost comes from method calls; there’s no per-second penalty in the quota table.) ([Google for Developers][7])
* **PKCE**: `code_challenge`/`code_verifier` flow is used with `launchWebAuthFlow` and your **Web application** client; Google recommends PKCE for browser-facing clients. ([Google for Developers][8])

---

### Troubleshooting

* **`redirect_uri_mismatch`**: Ensure the **exact** URI shown in Options is added to the OAuth Client’s **Authorized redirect URIs**. The pattern must be `https://<extension-id>.chromiumapp.org/...` from `getRedirectURL`. ([Chrome for Developers][1])
* **Insufficient scopes (403)**: Make sure you authorized with a scope that allows playlist writes (e.g., `youtube.force-ssl`). Re-authenticate after changing scopes. ([Google for Developers][5])
* **Edge vs Chrome**: Use `launchWebAuthFlow` (supported); avoid `getAuthToken` on Edge. ([Microsoft Learn][2])

---

### References (documentation & facts)

* Chrome/Edge extension identity & redirect: “chrome.identity (getRedirectURL/launchWebAuthFlow)” — developers.chrome.com; “Supported APIs for Microsoft Edge extensions” — learn.microsoft.com. ([Chrome for Developers][1], [Microsoft Learn][2])
* YouTube API basics & OAuth: “Implementing OAuth 2.0 Authorization” — developers.google.com. PKCE guidance for installed apps — YouTube Data API auth for installed apps. ([Google for Developers][4])
* Uploads playlist discovery: `channels.list (part=contentDetails → relatedPlaylists.uploads)` — developers.google.com. ([Google for Developers][3])
* Playlist list/insert + playlist items list/insert (quota costs, pagination): YouTube Quota Calculator; `playlistItems.list`; `playlists.insert`; `playlistItems.insert` (and constraint about Uploads). ([Google for Developers][7])
* Default daily quota and reset time: YouTube “Quota and Compliance Audits” page. ([Google for Developers][9])

```
Plain-text URLs (for your notes)
developer.chrome.com/docs/extensions/reference/api/identity
learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/api-support
developers.google.com/youtube/v3/docs/channels/list
developers.google.com/youtube/v3/docs/playlistItems/list
developers.google.com/youtube/v3/docs/playlists/insert
developers.google.com/youtube/v3/docs/playlistItems/insert
developers.google.com/youtube/v3/determine_quota_cost
developers.google.com/youtube/v3/guides/quota_and_compliance_audits
developers.google.com/youtube/v3/guides/authentication
developers.google.com/youtube/v3/guides/auth/installed-apps
```

If you want, tell me the exact **playlist title** and **privacy** you prefer as defaults; I’ll fold those into the code and add a one-click “Dry-run (no inserts)” toggle for verification.

[1]: https://developer.chrome.com/docs/extensions/reference/api/identity?utm_source=chatgpt.com "chrome.identity | API - Chrome for Developers"
[2]: https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/api-support?utm_source=chatgpt.com "Supported APIs for Microsoft Edge extensions"
[3]: https://developers.google.com/youtube/v3/docs/channels/list?utm_source=chatgpt.com "Channels: list | YouTube Data API"
[4]: https://developers.google.com/youtube/v3/guides/authentication?utm_source=chatgpt.com "Implementing OAuth 2.0 Authorization | YouTube Data API"
[5]: https://developers.google.com/resources/api-libraries/documentation/youtube/v3/cpp/latest/classgoogle__youtube__api_1_1YouTubeService_1_1SCOPES.html?utm_source=chatgpt.com "youtube: google_youtube_api::YouTubeService::SCOPES ..."
[6]: https://developers.google.com/youtube/v3/docs/playlistItems/list?utm_source=chatgpt.com "PlaylistItems: list | YouTube Data API"
[7]: https://developers.google.com/youtube/v3/determine_quota_cost "Quota Calculator  |  YouTube Data API  |  Google for Developers"
[8]: https://developers.google.com/youtube/v3/guides/auth/installed-apps?utm_source=chatgpt.com "OAuth 2.0 for Mobile & Desktop Apps | YouTube Data API"
[9]: https://developers.google.com/youtube/v3/guides/quota_and_compliance_audits?utm_source=chatgpt.com "Quota and Compliance Audits | YouTube Data API"

### option 2 (url:https://www.youtube.com/playlist?list=[target] - paste in console)(e.g. list=PLoervgkkJMu5E0wFZJ8bR1w57Uy63E3xn)(verified)
```js
(() => {
  const listBox = document.querySelector('div[role="listbox"][aria-label="Youtube Grid"]')

  let lastCount  = 0;
  let lastHeight = 0;

  // scroll iteratively poplulates all videos
  const scr = setInterval(() => {
    listBox.scrollTop = listBox.scrollHeight;
    listBox.dispatchEvent(new Event('scroll')); 
    const nowCount  = listBox.querySelectorAll('div[role="option"]').length;
    const nowHeight = listBox.scrollHeight;
    if (nowCount !== lastCount || nowHeight !== lastHeight) {
      lastCount  = nowCount;
      lastHeight = nowHeight;
      listBox.scrollTop = listBox.scrollHeight;
      listBox.dispatchEvent(new Event('scroll')); 
    } else {
      clearInterval(scr);
      const elems = Array.from(document.querySelectorAll('div[jsaction*="mouseenter:"][role="option"]'));
      const I = elems.length;

      if (!I) 
        return;
      
      // each item subscribes a handler on the bus
      for (const el of elems) {
        el.invokeclick = (i) => {
            if (i<I) {
                el.click();
                const next = i + 1;
                if (next<I)
                  setTimeout(() => { elems[next].invokeclick(next); }, 650);
                else {              
                  const doneBtn = document.querySelectorAll('button')[2]; 
                  doneBtn?.click();
                }
            } else {              
              const doneBtn = document.querySelectorAll('button')[2]; doneBtn?.click();
            }
        };
      }
      
      // start the invoke chain
      elems[0].invokeclick(0);
    }
  }, 1650);
})();
```