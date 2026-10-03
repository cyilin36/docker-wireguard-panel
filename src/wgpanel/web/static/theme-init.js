'use strict';

/* First-paint theme bootstrap.
 *
 * Loaded synchronously from <head> *before* the stylesheet so the very first
 * paint already carries the right palette — anything later (defer, DOMContentLoaded,
 * a module) shows a white flash to dark-mode users and a black one to light-mode
 * users. Keep this file tiny and synchronous: no fetch, no imports, no layout reads.
 *
 * Contract, shared with theme.js and both pages:
 *   localStorage["wgpanel.theme"] in {"auto", "light", "dark"}   ("auto" = follow the OS)
 *   <html data-theme="light"|"dark">                             (resolved, what CSS reads)
 *
 * With no stored choice and no readable system preference the answer is "light":
 * the day palette is the default.
 */
(function () {
  const KEY = 'wgpanel.theme';
  const root = document.documentElement;

  /* Storage can throw (Safari private mode, disabled cookies, a sandboxed frame).
     Reads and writes are both guarded, and a write that fails is remembered here
     so the choice still holds for this page: otherwise `choice()` would fall back
     to "auto" and the pressed segment would claim the wrong mode. */
  let fallback = 'auto';

  function normalise(value) {
    return value === 'light' || value === 'dark' || value === 'auto' ? value : null;
  }

  function stored() {
    try {
      return normalise(localStorage.getItem(KEY)) || fallback;
    } catch (_) {
      return fallback;
    }
  }

  /* Unknown or unsupported system preference resolves to light, not dark. */
  function systemPrefersDark() {
    try {
      return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (_) {
      return false;
    }
  }

  function resolve(choice) {
    if (choice === 'light' || choice === 'dark') return choice;
    return systemPrefersDark() ? 'dark' : 'light';
  }

  function apply(choice) {
    const theme = resolve(choice);
    root.setAttribute('data-theme', theme);
    /* Drives native widgets — scrollbars, number spinners, autofill — and keeps
       form controls from rendering as light-on-light. */
    root.style.colorScheme = theme;
    return theme;
  }

  const api = {
    KEY: KEY,
    choice: stored,
    resolve: resolve,
    systemPrefersDark: systemPrefersDark,
    current: function () {
      return root.getAttribute('data-theme');
    },
    /* Switching in place: no reload, so nothing on screen can flicker. */
    set: function (choice) {
      fallback = choice;
      try {
        if (choice === 'auto') localStorage.removeItem(KEY);
        else localStorage.setItem(KEY, choice);
      } catch (_) { /* the in-memory fallback above carries this page */ }
      return apply(choice);
    },
    sync: function () {
      return apply(stored());
    },
    onChange: function (handler) {
      try {
        matchMedia('(prefers-color-scheme: dark)').addEventListener('change', handler);
      } catch (_) { /* no dynamic follow-up; the initial resolution still holds */ }
    },
  };

  apply(api.choice());
  window.wgTheme = api;
})();
