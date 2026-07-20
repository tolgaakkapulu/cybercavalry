/* CYBERCavalry — App JS */

// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function () {
  const alerts = document.querySelectorAll('.alert[data-auto-dismiss]');
  alerts.forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity 0.4s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 400);
    }, 5000);
  });
});

// Copy to clipboard helper (used for API token display)
function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function () {
      showToast('Copied to clipboard');
    });
  }
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'alert alert-success';
  toast.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;min-width:200px;';
  toast.setAttribute('data-auto-dismiss', '1');
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(function () {
    toast.style.transition = 'opacity 0.4s';
    toast.style.opacity = '0';
    setTimeout(function () { toast.remove(); }, 400);
  }, 3000);
}

// ── PDF download with a precise loading overlay ──────────────────────────
// Why: the old pattern (window.location.href = url + window 'focus' listener)
// kept the "Generating PDF…" modal open until the user happened to focus
// another tab/window — when the browser saved the file silently in the
// background, the overlay stayed visible until a 20-second fallback fired.
// Fetching the PDF as a Blob lets us close the overlay the instant bytes
// finish arriving, then trigger an <a download> click for the actual save.
// The filename is read from the server's Content-Disposition header.
window.downloadPdfWithOverlay = function (url, overlayId, fallbackName) {
  var overlay = overlayId ? document.getElementById(overlayId) : null;
  if (overlay) overlay.style.display = 'flex';

  var cleanup = function () { if (overlay) overlay.style.display = 'none'; };

  return fetch(url, { credentials: 'same-origin' })
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var cd = res.headers.get('Content-Disposition') || '';
      // Prefer RFC 5987 filename* (UTF-8'') if present, fall back to filename=.
      var m = cd.match(/filename\*\s*=\s*[^']*''([^;]+)/i)
           || cd.match(/filename\s*=\s*"?([^";]+)"?/i);
      var filename = m ? decodeURIComponent(m[1].trim()) : (fallbackName || 'report.pdf');
      return res.blob().then(function (blob) { return { blob: blob, filename: filename }; });
    })
    .then(function (r) {
      var blobUrl = URL.createObjectURL(r.blob);
      var a = document.createElement('a');
      a.href = blobUrl;
      a.download = r.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(blobUrl); }, 1000);
      cleanup();
    })
    .catch(function (e) {
      cleanup();
      console.error('PDF download failed:', e);
      window.alert('PDF download failed: ' + e.message);
    });
};

// LDAP test via Alpine.js
window.testLDAPConnection = function () {
  return fetch('/settings/ldap/test/', {
    method: 'POST',
    headers: {
      'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]')?.value || '',
    }
  })
  .then(r => r.json())
  .then(data => data.message || (data.success ? 'Connected' : 'Failed'))
  .catch(e => 'Error: ' + e.message);
};

// Portal-style tooltip for `.info-tip.info-tip-float[data-tip]`. The default
// CSS-only info-tip renders its ::after pseudo-element inside the icon's own
// stacking context — fine everywhere except inside scrollable table wrappers
// (`.table-wrapper { overflow:auto }`), where it either gets clipped by the
// wrapper or paints behind subsequent rows. This portal moves the tip node
// into <body> on hover, positions it with `position:fixed` at the maximum
// z-index, and removes it on leave. Add the class on any tooltip that lives
// inside a scrollable/overflow container.
(function () {
  let floater = null;

  function ensureFloater() {
    if (floater) return floater;
    floater = document.createElement('div');
    floater.className = 'info-tip-floater';
    document.body.appendChild(floater);
    return floater;
  }

  function position(el) {
    const rect = el.getBoundingClientRect();
    const f = floater;
    // Two-frame position: first render measures floater height, second frame
    // aligns it to the icon vertically. Prevents a first-hover jump.
    f.style.left = (rect.right + 10) + 'px';
    f.style.top  = (rect.top + rect.height / 2) + 'px';
    requestAnimationFrame(() => {
      f.style.top = (rect.top + rect.height / 2 - f.offsetHeight / 2) + 'px';
      f.classList.add('visible');
    });
  }

  function show(el) {
    const tip = el.getAttribute('data-tip');
    if (!tip) return;
    ensureFloater();
    floater.textContent = tip;
    position(el);
  }

  function hide() {
    if (floater) floater.classList.remove('visible');
  }

  document.addEventListener('pointerover', (e) => {
    const el = e.target.closest('.info-tip.info-tip-float');
    if (el) show(el);
  });
  document.addEventListener('pointerout', (e) => {
    const el = e.target.closest('.info-tip.info-tip-float');
    if (el) hide();
  });
  // Reposition on scroll so the tip tracks the icon while the wrapper scrolls.
  document.addEventListener('scroll', () => hide(), true);
})();
