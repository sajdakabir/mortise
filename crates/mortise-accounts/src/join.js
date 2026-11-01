const token = location.hash.slice(1);
const button = document.querySelector('#open');
const status = document.querySelector('#status');
if (/^[a-f0-9]{64}$/.test(token)) {
  button.disabled = false;
  status.textContent = 'Mortise must be installed on this Mac. Opening the link does not grant access.';
  button.addEventListener('click', () => {
    const payload = btoa(JSON.stringify({ server: location.origin, token }))
      .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    location.href = `mortise://team-invite#${payload}`;
  });
} else {
  status.textContent = 'This invitation link is incomplete. Ask for a new link.';
}
