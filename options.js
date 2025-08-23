
const $ = s => document.querySelector(s);

// popup.js / options.js / aync batchable optional
function sendMessageAsync(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (resp) => {
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        resolve(resp);
        return true;
      });
    } catch (e) {
      reject(e);
    }
  });
}

async function init() {
  const { redirectUri } = await chrome.runtime.sendMessage({ type: 'getRedirectUri' });
  $('#redir').textContent = redirectUri;

  const { google_oauth_client_id } = await chrome.storage.local.get(['google_oauth_client_id']);
  const { google_oauth_client_secret } = await chrome.storage.local.get(['google_oauth_client_secret']);

  if (google_oauth_client_id)
    $('#clientId').value = google_oauth_client_id;
  if (google_oauth_client_secret)
    $('#clientSecret').value = google_oauth_client_secret;
  
}

init();

$('#save').onclick = async () => {
  const clientId = $('#clientId').value.trim();
  const clientSecret = $('#clientSecret').value.trim();

  if (!clientId) { 
    $('#id_status').textContent = 'Enter a Client ID.';
  } else {
    const resp = await sendMessageAsync({ type: 'setClientId', clientId });
    $('#id_status').textContent = resp?.ok ? 'clientID Saved.' : 'Failed to save clientID.';
  }
  if (!clientSecret) { 
    $('#secret_status').textContent = 'Enter a Client SECRET.';
  } else {
    const resp = await sendMessageAsync({ type: 'setClientSecret', clientSecret });
    $('#secret_status').textContent = resp?.ok ? 'clientSecret Saved.' : 'Failed to save clientSecret.';
  }

};