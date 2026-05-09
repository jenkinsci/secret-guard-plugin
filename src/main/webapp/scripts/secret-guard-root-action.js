(function () {
    var DETAILS_PANEL_ID = "secret-guard-scan-all-details";
    var DETAILS_TOGGLE_ID = "secret-guard-scan-all-details-toggle";
    var SCAN_DIALOG_ID = "secret-guard-scan-all-dialog";
    var OPEN_SCAN_DIALOG_BUTTON_ID = "secret-guard-open-scan-all-dialog";
    var CLOSE_SCAN_DIALOG_BUTTON_ID = "secret-guard-close-scan-all-dialog";
    var RESULTS_SECTION_ID = "secret-guard-results-section";
    var RESULTS_LINK_CLASS = "secret-guard-results-link";
    var RESULTS_SEARCH_FORM_CLASS = "secret-guard-results-search";
    var RESULTS_FILTER_PARAM = "filter";
    var RESULTS_QUERY_PARAM = "q";
    var STORAGE_KEY_SUFFIX = ":scan-all-details-open";
    var activeResultsRequest = null;
    var activeResultsRequestUrl = null;
    var activeResultsAbortController = null;
    var resultsRequestSequence = 0;

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
        panel.hidden = false;
        panel.classList.toggle("jenkins-hidden", !open);
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
            setDetailsOpen(panel, toggle, panel.classList.contains("jenkins-hidden"), true);
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

        resultsSection.querySelectorAll("." + RESULTS_SEARCH_FORM_CLASS + ' button[type="submit"]').forEach(function (button) {
            button.disabled = loading;
        });
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
        if (activeResultsRequest && activeResultsRequestUrl === url) {
            return activeResultsRequest;
        }

        if (activeResultsAbortController) {
            activeResultsAbortController.abort();
            activeResultsAbortController = null;
        }

        resultsRequestSequence += 1;
        var requestSequence = resultsRequestSequence;
        var requestOptions = {
            headers: {
                "X-Requested-With": "XMLHttpRequest"
            },
            credentials: "same-origin"
        };
        if (typeof window.AbortController === "function") {
            activeResultsAbortController = new window.AbortController();
            requestOptions.signal = activeResultsAbortController.signal;
        }

        activeResultsRequestUrl = url;
        setResultsLoading(true);

        activeResultsRequest = window.fetch(url, requestOptions).then(function (response) {
            if (!response.ok) {
                throw new Error("Failed to load filtered results.");
            }
            return response.text();
        }).then(function (html) {
            if (requestSequence !== resultsRequestSequence) {
                return;
            }

            var parser = new DOMParser();
            var nextDocument = parser.parseFromString(html, "text/html");
            if (!replaceResultsSection(nextDocument)) {
                window.location.assign(url);
                return;
            }

            if (pushHistory) {
                window.history.pushState({resultsUrl: url}, "", url);
            }
        }).catch(function (error) {
            if (error && error.name === "AbortError") {
                return;
            }
            window.location.assign(url);
        }).finally(function () {
            if (requestSequence === resultsRequestSequence) {
                activeResultsRequest = null;
                activeResultsRequestUrl = null;
                activeResultsAbortController = null;
                setResultsLoading(false);
            }
        });

        return activeResultsRequest;
    }

    function buildResultsFormUrl(form) {
        var action = form.getAttribute("action") || window.location.pathname;
        var params = new window.URLSearchParams();

        // Avoid serializing Jenkins-injected hidden fields such as crumbs into the GET URL.
        appendResultsFormField(form, params, RESULTS_FILTER_PARAM);
        appendResultsFormField(form, params, RESULTS_QUERY_PARAM);

        var query = params.toString();
        return query ? action + "?" + query : action;
    }

    function appendResultsFormField(form, params, fieldName) {
        var field = form.elements.namedItem(fieldName);
        if (!field || typeof field.value !== "string") {
            return;
        }

        var normalizedValue = field.value.trim();
        if (normalizedValue === "") {
            return;
        }

        params.append(fieldName, normalizedValue);
    }

    function initializeFilterRefresh() {
        document.addEventListener("click", function (event) {
            var link = event.target.closest("." + RESULTS_LINK_CLASS);
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

        document.addEventListener("submit", function (event) {
            var form = event.target.closest("." + RESULTS_SEARCH_FORM_CLASS);
            if (!form) {
                return;
            }

            var resultsSection = document.getElementById(RESULTS_SECTION_ID);
            if (!resultsSection || !resultsSection.contains(form)) {
                return;
            }

            event.preventDefault();
            fetchAndReplaceResults(buildResultsFormUrl(form), true);
        });

        window.addEventListener("popstate", function () {
            fetchAndReplaceResults(window.location.href, false);
        });
    }

    function showScanDialog(dialog) {
        if (typeof dialog.showModal === "function") {
            dialog.showModal();
            return;
        }

        dialog.setAttribute("open", "open");
    }

    function closeScanDialog(dialog) {
        if (typeof dialog.close === "function") {
            dialog.close();
            return;
        }

        dialog.removeAttribute("open");
    }

    function initializeScanDialog() {
        var openButton = document.getElementById(OPEN_SCAN_DIALOG_BUTTON_ID);
        var dialog = document.getElementById(SCAN_DIALOG_ID);
        var closeButton = document.getElementById(CLOSE_SCAN_DIALOG_BUTTON_ID);
        if (!openButton || !dialog || !closeButton) {
            return;
        }

        openButton.addEventListener("click", function () {
            if (openButton.disabled) {
                return;
            }

            showScanDialog(dialog);
            var firstInput = dialog.querySelector("input");
            if (firstInput) {
                firstInput.focus();
            }
        });

        closeButton.addEventListener("click", function () {
            closeScanDialog(dialog);
            openButton.focus();
        });
    }

    function initialize() {
        initializeDetailsState();
        initializeScanDialog();
        initializeFilterRefresh();
        scheduleRefresh();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize, {once: true});
        return;
    }

    initialize();
})();
