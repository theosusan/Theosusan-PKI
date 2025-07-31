// Gestion du bouton déconnexion
function setupLogoutButton() {
  const logoutBtn = document.getElementById('logoutBtn');
  if (!logoutBtn) return;

  logoutBtn.addEventListener('click', async () => {
    await fetch('/logout', { method: 'POST' });
    window.location.href = '/';
  });
}



// Fonction pour afficher un toast (message d’info ou d’erreur)
function showToast(message, isSuccess = true) {
  const toastEl = document.getElementById('liveToast');
  const toastBody = document.getElementById('toastBody');
  
  toastBody.textContent = message;
  
  toastEl.classList.remove('bg-success', 'bg-danger', 'text-white');
  
  if (isSuccess) {
    toastEl.classList.add('bg-success', 'text-white');
    var toast = new bootstrap.Toast(toastEl, { autohide: true, delay: 5000 });
  } else {
    toastEl.classList.add('bg-danger', 'text-white');
    var toast = new bootstrap.Toast(toastEl, { autohide: true, delay: 10000 });
  }
  
  toast.show();
}

const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebarToggle');
const sidebarBackdrop = document.getElementById('sidebarBackdrop');
const logoutBtn = document.getElementById('logoutBtn');

// format date
function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr; // si format inattendu
  
  const pad = (n) => n.toString().padStart(2, '0');
  
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function displayKey(keyContent, title, keyName = '') {
  const keyDisplay = document.getElementById('keyDisplay');
  const keyDisplayContent = document.getElementById('keyDisplayContent');
  
  keyDisplayContent.innerHTML = `${title} ${keyName} :<br><br>${keyContent.trim().replace(/\n/g, '<br>')}`;
  keyDisplay.style.display = 'block';
}

function setupCloseKeyDisplay() {
  const closeBtn = document.getElementById('closeKeyDisplay');
  if (!closeBtn) return;

  closeBtn.addEventListener('click', () => {
    const keyDisplay = document.getElementById('keyDisplay');
    const keyDisplayContent = document.getElementById('keyDisplayContent');

    keyDisplayContent.textContent = '';
    keyDisplay.style.display = 'none';
  });
}