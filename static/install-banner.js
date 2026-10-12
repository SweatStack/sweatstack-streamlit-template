/*
 * "Install this app" banner. proxy.py adds this script to every page when
 * manifest.json exists and PWA_INSTALL_BANNER is not false, with settings in
 * data attributes on the <script> tag.
 *
 * - Chrome, Edge, Samsung Internet (Android and desktop): once the browser
 *   reports the app as installable, show an "Install" button that opens the
 *   browser's own install dialog.
 * - iPhone and iPad: there is no install API, so explain how to use
 *   Share → "Add to Home Screen".
 * - Other browsers, or when the app is already installed: nothing.
 *
 * Only logged-in users see the banner. For logged-out visitors the browser's
 * own install prompt is suppressed too, so nobody is asked to install the
 * login page. Closing the banner hides it for 30 days in that browser.
 */
(() => {
  "use strict";

  const config = document.currentScript.dataset;
  const appName = config.appName || document.title;
  const backgroundColor = config.themeColor || "#ffffff";
  const authenticated = config.authenticated === "true";

  const DISMISSED_KEY = "pwa-install-banner-dismissed-at";
  const SNOOZE_MS = 30 * 24 * 60 * 60 * 1000;
  const BANNER_ID = "pwa-install-banner";

  const isInstalled =
    window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  // iPadOS reports itself as a Mac; touch support gives it away.
  const isIOS =
    /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);

  function isSnoozed() {
    try {
      return Date.now() - Number(localStorage.getItem(DISMISSED_KEY)) < SNOOZE_MS;
    } catch {
      return false; // Storage blocked: show the banner, dismissal lasts until reload.
    }
  }

  function snooze() {
    try {
      localStorage.setItem(DISMISSED_KEY, String(Date.now()));
    } catch {
      // Storage blocked: nothing to remember.
    }
  }

  function textColorFor(hex) {
    const match = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex);
    if (!match) return "#000000";
    const digits = match[1].length === 3 ? match[1].replace(/./g, "$&$&") : match[1];
    const [r, g, b] = [0, 2, 4].map((i) => {
      const channel = parseInt(digits.slice(i, i + 2), 16) / 255;
      return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    });
    const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    return luminance > 0.179 ? "#000000" : "#ffffff";
  }

  function whenBodyReady(callback) {
    if (document.body) callback();
    else document.addEventListener("DOMContentLoaded", callback, { once: true });
  }

  function element(tag, styles, text) {
    const node = document.createElement(tag);
    Object.assign(node.style, styles);
    if (text) node.textContent = text;
    return node;
  }

  function shareIcon(color) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "18");
    svg.setAttribute("height", "18");
    svg.setAttribute("aria-label", "Share");
    svg.style.verticalAlign = "-3px";
    svg.style.margin = "0 2px";
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M12 3v12M7.5 7.5 12 3l4.5 4.5M8 11H6v10h12V11h-2");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", color);
    path.setAttribute("stroke-width", "1.8");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    svg.appendChild(path);
    return svg;
  }

  function removeBanner() {
    document.getElementById(BANNER_ID)?.remove();
  }

  // `message` is a list of strings and DOM nodes. `action` is an optional
  // { label, onClick } for a button next to the close button.
  function showBanner(message, action) {
    removeBanner();
    const textColor = textColorFor(backgroundColor);

    const banner = element("div", {
      position: "fixed",
      left: "0",
      right: "0",
      bottom: "0",
      zIndex: "1000000",
      display: "flex",
      alignItems: "center",
      gap: "12px",
      padding: "12px 16px calc(12px + env(safe-area-inset-bottom))",
      background: backgroundColor,
      color: textColor,
      borderTop: "1px solid rgba(0, 0, 0, 0.1)",
      boxShadow: "0 -2px 8px rgba(0, 0, 0, 0.15)",
      font: "14px/1.4 system-ui, -apple-system, sans-serif",
    });
    banner.id = BANNER_ID;
    banner.setAttribute("role", "dialog");
    banner.setAttribute("aria-label", `Install ${appName}`);

    const text = element("div", { flex: "1" });
    text.append(...message);
    banner.appendChild(text);

    if (action) {
      const button = element(
        "button",
        {
          padding: "8px 14px",
          border: "none",
          borderRadius: "6px",
          background: textColor,
          color: backgroundColor,
          font: "inherit",
          fontWeight: "600",
          cursor: "pointer",
        },
        action.label,
      );
      button.addEventListener("click", action.onClick);
      banner.appendChild(button);
    }

    const close = element(
      "button",
      {
        padding: "0 4px",
        border: "none",
        background: "none",
        color: "inherit",
        fontSize: "22px",
        lineHeight: "1",
        cursor: "pointer",
      },
      "×",
    );
    close.setAttribute("aria-label", "Dismiss");
    close.addEventListener("click", () => {
      snooze();
      removeBanner();
    });
    banner.appendChild(close);

    document.body.appendChild(banner);
  }

  function title() {
    return element("strong", {}, `Install ${appName}`);
  }

  // Chromium browsers: fired when the app is installable and not yet installed.
  window.addEventListener("beforeinstallprompt", (event) => {
    // Always replace the browser's own install prompt with ours (or with nothing).
    event.preventDefault();
    if (!authenticated || isSnoozed()) return;
    whenBodyReady(() =>
      showBanner([title(), " for quick access from your home screen or desktop."], {
        label: "Install",
        onClick: async () => {
          event.prompt();
          await event.userChoice;
          removeBanner();
        },
      }),
    );
  });

  window.addEventListener("appinstalled", removeBanner);

  if (isIOS && authenticated && !isInstalled && !isSnoozed()) {
    whenBodyReady(() =>
      showBanner([
        title(),
        ": tap ",
        shareIcon(textColorFor(backgroundColor)),
        " Share, then “Add to Home Screen”.",
      ]),
    );
  }
})();
