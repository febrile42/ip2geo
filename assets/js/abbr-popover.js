/**
 * Tap-to-explain for DROP labels (abbr.drop-tag and the summary line's abbr).
 *
 * Native title tooltips only appear on hover, so phones never saw the
 * explanation. Tap/click (or Enter/Space when focused) opens a small popover
 * with the abbr's title text; tapping it again, tapping elsewhere, or Esc
 * closes it. Delegated on document, so it covers both the server-rendered
 * table and rows the workbench renders later.
 *
 *   tap abbr ──▶ open? same abbr ──yes──▶ close
 *                 │no
 *                 ▼
 *   close any open ─▶ render .abbr-pop (role=tooltip) under the abbr,
 *                     clamped to the viewport; aria-describedby → popover
 *
 * UMD: window.ip2geoAbbrPopover in the browser, module.exports for Jest.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ip2geoAbbrPopover = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SELECTOR = 'abbr.drop-tag, .lookup-summary-drop abbr';
  var POP_ID = 'abbr-pop';

  function install(doc) {
    doc = doc || document;
    var win = doc.defaultView || window;
    var openFor = null;

    function close() {
      var pop = doc.getElementById(POP_ID);
      if (pop) pop.remove();
      if (openFor) {
        openFor.removeAttribute('aria-describedby');
        openFor.setAttribute('aria-expanded', 'false');
      }
      openFor = null;
    }

    function open(target) {
      close();
      var text = target.getAttribute('title') || target.getAttribute('data-tip') || '';
      if (!text) return;
      var pop = doc.createElement('div');
      pop.id = POP_ID;
      pop.className = 'abbr-pop';
      pop.setAttribute('role', 'tooltip');
      pop.textContent = text;
      doc.body.appendChild(pop);

      var r = target.getBoundingClientRect();
      var scrollX = win.pageXOffset || 0, scrollY = win.pageYOffset || 0;
      var vw = doc.documentElement.clientWidth || win.innerWidth || 320;
      var width = pop.offsetWidth || 280;
      var left = Math.max(8, Math.min(r.left, vw - width - 8));
      pop.style.left = (left + scrollX) + 'px';
      pop.style.top = (r.bottom + scrollY + 6) + 'px';

      target.setAttribute('aria-describedby', POP_ID);
      target.setAttribute('aria-expanded', 'true');
      openFor = target;
    }

    function toggle(target) {
      if (openFor === target) close(); else open(target);
    }

    // Make labels keyboard-reachable wherever they render.
    function prime(scope) {
      (scope || doc).querySelectorAll(SELECTOR).forEach(function (a) {
        if (!a.hasAttribute('tabindex')) a.setAttribute('tabindex', '0');
        if (!a.hasAttribute('aria-expanded')) a.setAttribute('aria-expanded', 'false');
      });
    }

    doc.addEventListener('click', function (e) {
      var target = e.target.closest && e.target.closest(SELECTOR);
      if (target) { e.preventDefault(); toggle(target); return; }
      if (openFor && !(e.target.closest && e.target.closest('#' + POP_ID))) close();
    });
    doc.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && openFor) { var t = openFor; close(); t.focus(); return; }
      var target = e.target.closest && e.target.closest(SELECTOR);
      if (target && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggle(target); }
    });
    win.addEventListener('resize', close);

    prime(doc);
    // The workbench renders rows after lookups; prime them as they appear.
    if (win.MutationObserver) {
      new win.MutationObserver(function () { prime(doc); })
        .observe(doc.body, { childList: true, subtree: true });
    }

    return { open: open, close: close, toggle: toggle, prime: prime, isOpen: function () { return openFor; } };
  }

  return { install: install, SELECTOR: SELECTOR };
}));

if (typeof window !== 'undefined' && typeof document !== 'undefined' && !(typeof module === 'object' && module.exports)) {
  window.ip2geoAbbrPopover.install(document);
}
