(function () {
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

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scheduleRefresh, {once: true});
        return;
    }

    scheduleRefresh();
})();
