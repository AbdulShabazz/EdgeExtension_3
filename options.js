
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