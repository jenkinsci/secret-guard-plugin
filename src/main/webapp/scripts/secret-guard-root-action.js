(function () {
    var DETAILS_PANEL_ID = "secret-guard-scan-all-details";
    var DETAILS_TOGGLE_ID = "secret-guard-scan-all-details-toggle";
    var STORAGE_KEY_SUFFIX = ":scan-all-details-open";

    function getSessionStorage() {
        try {
            return window.sessionStorage;
        } catch (ignored) {
            return null;
        }
    }

    function getDetailsStorageKey() {
        return window.location.pathname + STORAGE_KEY_SUFFIX;
    }

    function persistDetailsState(open) {
        var storage = getSessionStorage();
        if (!storage) {
            return;
        }

        storage.setItem(getDetailsStorageKey(), open ? "true" : "false");
    }

    function setDetailsOpen(panel, toggle, open, persist) {
        panel.hidden = !open;
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        toggle.textContent = open ? "Hide Details" : "Details";
        if (persist) {
            persistDetailsState(open);
        }
    }

    function initializeDetailsState() {
        var panel = document.getElementById(DETAILS_PANEL_ID);
        var toggle = document.getElementById(DETAILS_TOGGLE_ID);
        if (!panel || !toggle) {
            return;
        }

        var storage = getSessionStorage();
        var storedValue = storage ? storage.getItem(getDetailsStorageKey()) : null;
        var open = toggle.getAttribute("aria-expanded") === "true";
        if (storedValue === "true") {
            open = true;
        } else if (storedValue === "false") {
            open = false;
        }

        setDetailsOpen(panel, toggle, open, false);

        toggle.addEventListener("click", function () {
            setDetailsOpen(panel, toggle, panel.hidden, true);
        });

        persistDetailsState(open);
    }

    function hasRunningScanControls() {
        return document.querySelector('form[action$="cancelScanAll"]') !== null;
    }

    function scheduleRefresh() {
        var refreshMarker = document.getElementById("secret-guard-auto-refresh");
        if (!refreshMarker && !hasRunningScanControls()) {
            return;
        }

        var interval = refreshMarker ? Number.parseInt(refreshMarker.dataset.intervalMs, 10) : Number.NaN;
        if (Number.isNaN(interval) || interval <= 0) {
            interval = 3000;
        }

        window.setTimeout(function () {
            window.location.reload();
        }, interval);
    }

    function initialize() {
        initializeDetailsState();
        scheduleRefresh();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize, {once: true});
        return;
    }

    initialize();
})();
