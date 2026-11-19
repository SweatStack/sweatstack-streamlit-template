/*
 * Keeps the sign-in fresh while the page is open. Injected by proxy.py on signed-in pages.
 *
 * Why it exists: SweatStack rotates refresh tokens, so only the proxy's cookie may hold one,
 * and only a response to the browser can rewrite that cookie. A long-open Streamlit tab sends
 * no such requests (it talks over its WebSocket), so this script asks the proxy to refresh
 * shortly before the access token expires. The Streamlit session then fetches the new access
 * token from the proxy.
 *
 * POST /_proxy/refresh refreshes only when the token expires within 5 minutes, so calling it
 * early or often costs nothing. Its answer is a duration (`expires_in`), never a time, so a
 * wrong clock on this device does not matter.
 */
(function () {
  "use strict";

  var LEAD_SECONDS = 180; // ask 3 minutes early: hidden tabs run timers at most once a minute
  var MIN_DELAY_SECONDS = 5; // never ask more often than this, whatever the answer
  // After a failed call. Within SweatStack's 30-second grace period, so that if a refresh went
  // through but its answer was lost, the retry still gets the same new token.
  var RETRY_SECONDS = 10;
  var LOCK_NAME = "sweatstack-refresh";

  var dueAt = 0; // Date.now() at which the next refresh is due
  var timer = null;

  function schedule(seconds) {
    clearTimeout(timer);
    var delay = Math.max(MIN_DELAY_SECONDS, seconds) * 1000;
    dueAt = Date.now() + delay;
    timer = setTimeout(refresh, delay);
  }

  function untilNext(expiresIn) {
    // 3 minutes before expiry; for a token that lives shorter than twice that, halfway.
    return expiresIn - Math.min(LEAD_SECONDS, expiresIn / 2);
  }

  function handle(response) {
    if (response.status === 401) {
      // The sign-in is over (signed out elsewhere, or ended at SweatStack): show sign-in.
      location.reload();
      return;
    }
    if (!response.ok) {
      schedule(RETRY_SECONDS);
      return;
    }
    return response.json().then(
      function (body) {
        var valid = body && typeof body.expires_in === "number" && isFinite(body.expires_in);
        schedule(valid ? untilNext(body.expires_in) : RETRY_SECONDS);
      },
      function () {
        schedule(RETRY_SECONDS);
      }
    );
  }

  function call() {
    return fetch("/_proxy/refresh", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "X-SweatStack-Refresh": "1" },
    }).then(handle, function () {
      schedule(RETRY_SECONDS); // offline or the server is restarting
    });
  }

  function refresh() {
    // One tab at a time: the next tab's call then carries the cookie the first one received.
    if (navigator.locks && navigator.locks.request) {
      navigator.locks.request(LOCK_NAME, call).catch(function () {
        schedule(RETRY_SECONDS);
      });
    } else {
      call();
    }
  }

  function catchUp() {
    // A frozen or sleeping tab misses its timer; refresh as soon as it runs again.
    if (Date.now() >= dueAt) refresh();
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") catchUp();
  });
  window.addEventListener("online", catchUp);

  refresh(); // learns the first deadline, and refreshes now if the page opened late
})();
