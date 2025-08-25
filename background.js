
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
  CLIENT_SECRET: 'google_oauth_client_secret',
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

  const clientSecret = await getStore(STORE_KEYS.CLIENT_SECRET);
  if (!clientSecret) throw new Error('Missing Google OAuth Client SECRET. Open Options and set it.');

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
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });

  const newTokens = {
    access_token: tokenResp.access_token,
    client_secret: tokenResp.clientSecret,
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
    let msg = "";
    if (have.has(vid)) { skipped++; continue; }
    try {
      await addVideoToPlaylist(destId, vid);
      inserted++;
      await new Promise(r => setTimeout(r, delayMs));
    } catch (e) {
      errors++;
      msg = `Insert failed for ${vid}: ${e}`;
      //console.error('Insert failed for', vid, e);
    }
    // progress ping to popup
    chrome.runtime.sendMessage({
      type: 'progress',
      data: { inserted, skipped, errors, total: uploadIds.length, msg }
    }).catch(()=>{ /* popup may be closed */ });
  }
  return { inserted, skipped, errors, total: uploadIds.length };
}

// ---------- Message handling from popup ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type)
    {
      case 'getRedirectUri':
        // show the exact value to register in Google Cloud
        sendResponse({ redirectUri: chrome.identity.getRedirectURL('oauth2') });
        break;
      case 'setClientId':
        await setStore(STORE_KEYS.CLIENT_ID, msg.clientId.trim());
        sendResponse({ ok: true });
        break;
      case 'setClientSecret':
        await setStore(STORE_KEYS.CLIENT_SECRET, msg.clientSecret.trim());
        sendResponse({ ok: true });
        break;
      case 'login':
        try {
          const token = await getValidAccessToken(true);
          sendResponse({ ok: true, tokenPresent: !!token });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        break;
      case 'run':
        try {
          const result = await runBulkAdd(msg.options);
          sendResponse({ ok: true, result });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        break;
    }
  })();
  return true; // keep the message channel alive for async
});