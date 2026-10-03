'use strict';

/* Theme picker behaviour, loaded at the end of <body>.
 *
 * theme-init.js has already resolved and applied the palette; this file only
 * handles the three-state control, cross-tab sync and following the OS while the
 * choice is "auto". Without theme-init.js this file leaves the page alone.
 */
(function () {
  const api = window.wgTheme;
  if (!api) return;

  const buttons = Array.prototype.slice.call(
    document.querySelectorAll('[data-theme-choice]'),
  );

  function markPressed() {
    const choice = api.choice();
    buttons.forEach(function (button) {
      button.setAttribute('aria-pressed', String(button.dataset.themeChoice === choice));
    });
  }

  function select(choice) {
    api.set(choice);
    markPressed();
    document.dispatchEvent(new CustomEvent('wgthemechange', { detail: { choice: choice } }));
  }

  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      select(button.dataset.themeChoice);
    });
  });

  /* Only "auto" defers to the OS; an explicit light/dark choice must not be
     overridden by the system switching at dusk. */
  api.onChange(function () {
    if (api.choice() === 'auto') api.sync();
  });

  /* Another tab changed the preference. */
  window.addEventListener('storage', function (event) {
    if (event.key === null || event.key === api.KEY) {
      api.sync();
      markPressed();
    }
  });

  markPressed();
})();
