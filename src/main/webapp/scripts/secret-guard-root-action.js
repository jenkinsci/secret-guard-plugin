(function () {
    var DETAILS_PANEL_ID = "secret-guard-scan-all-details";
    var DETAILS_TOGGLE_ID = "secret-guard-scan-all-details-toggle";
    var RESULTS_SECTION_ID = "secret-guard-results-section";
    var FILTER_LINK_CLASS = "secret-guard-filter-link";
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

    function shouldHandleFilterClick(event, link) {
        return !!link
            && !event.defaultPrevented
            && event.button === 0
            && !event.metaKey
            && !event.ctrlKey
            && !event.shiftKey
            && !event.altKey
            && link.target !== "_blank";
    }

    function setResultsLoading(loading) {
        var resultsSection = document.getElementById(RESULTS_SECTION_ID);
        if (!resultsSection) {
            return;
        }

        if (loading) {
            resultsSection.setAttribute("aria-busy", "true");
            resultsSection.classList.add("secret-guard-results-section--loading");
        } else {
            resultsSection.removeAttribute("aria-busy");
            resultsSection.classList.remove("secret-guard-results-section--loading");
        }
    }

    function replaceResultsSection(nextDocument) {
        var currentSection = document.getElementById(RESULTS_SECTION_ID);
        var nextSection = nextDocument.getElementById(RESULTS_SECTION_ID);
        if (!currentSection || !nextSection) {
            return false;
        }

        currentSection.replaceWith(nextSection);
        return true;
    }

    function fetchAndReplaceResults(url, pushHistory) {
        setResultsLoading(true);

        return window.fetch(url, {
            headers: {
                "X-Requested-With": "XMLHttpRequest"
            },
            credentials: "same-origin"
        }).then(function (response) {
            if (!response.ok) {
                throw new Error("Failed to load filtered results.");
            }
            return response.text();
        }).then(function (html) {
            var parser = new DOMParser();
            var nextDocument = parser.parseFromString(html, "text/html");
            if (!replaceResultsSection(nextDocument)) {
                window.location.assign(url);
                return;
            }

            if (pushHistory) {
                window.history.pushState({resultsUrl: url}, "", url);
            }
        }).catch(function () {
            window.location.assign(url);
        }).finally(function () {
            setResultsLoading(false);
        });
    }

    function initializeFilterRefresh() {
        document.addEventListener("click", function (event) {
            var link = event.target.closest("." + FILTER_LINK_CLASS);
            if (!shouldHandleFilterClick(event, link)) {
                return;
            }

            var resultsSection = document.getElementById(RESULTS_SECTION_ID);
            if (!resultsSection || !resultsSection.contains(link)) {
                return;
            }

            event.preventDefault();
            fetchAndReplaceResults(link.href, true);
        });

        window.addEventListener("popstate", function () {
            fetchAndReplaceResults(window.location.href, false);
        });
    }

    function initialize() {
        initializeDetailsState();
        initializeFilterRefresh();
        scheduleRefresh();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize, {once: true});
        return;
    }

    initialize();
})();
