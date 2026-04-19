package io.jenkins.plugins.secretguard.listener;

import hudson.Util;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.PluginServletFilter;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.JobConfigEnforcementService;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.xml.transform.stream.StreamSource;
import jenkins.model.Jenkins;

public class SecretGuardJobConfigFilter implements Filter {
    private static final SecretGuardJobConfigFilter INSTANCE = new SecretGuardJobConfigFilter();

    private final JobConfigEnforcementService enforcementService = new JobConfigEnforcementService();

    @Initializer(after = InitMilestone.PLUGINS_STARTED)
    public static void register() throws ServletException {
        if (!PluginServletFilter.hasFilter(INSTANCE)) {
            PluginServletFilter.addFilter(INSTANCE);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest)
                || !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        RequestTarget target = RequestTarget.from(httpRequest);
        if (target == null) {
            chain.doFilter(request, response);
            return;
        }

        try (JobConfigSaveScanGuard.Scope ignored = JobConfigSaveScanGuard.filterManagedSave()) {
            Snapshot snapshot = captureSnapshot(target);
            BufferedResponseWrapper bufferedResponse = new BufferedResponseWrapper(httpResponse);
            chain.doFilter(request, bufferedResponse);

            if (bufferedResponse.hasFailureStatus()) {
                bufferedResponse.commitTo(httpResponse);
                return;
            }

            Job<?, ?> job = target.resolveJob();
            if (job == null) {
                bufferedResponse.commitTo(httpResponse);
                return;
            }

            SecretScanResult result =
                    enforcementService.scan(job, job.getConfigFile().asString(), ScanPhase.SAVE);
            if (!result.isBlocked()) {
                bufferedResponse.commitTo(httpResponse);
                return;
            }

            if (snapshot.originalConfigXml == null) {
                deleteCreatedJob(job);
            } else {
                restoreOriginalConfig(job, snapshot.originalConfigXml);
            }
            restoreSnapshotResult(snapshot);
            sendBlockedResponse(httpRequest, httpResponse, target, result);
        }
    }

    @Override
    public void destroy() {}

    private Snapshot captureSnapshot(RequestTarget target) throws IOException {
        Job<?, ?> existingJob = target.resolveJob();
        if (existingJob == null) {
            return new Snapshot(target.jobFullName, null, null);
        }
        return new Snapshot(
                existingJob.getFullName(),
                existingJob.getConfigFile().asString(),
                ScanResultStore.get().get(existingJob.getFullName()).orElse(null));
    }

    private void restoreOriginalConfig(Job<?, ?> job, String originalConfigXml) throws IOException {
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            job.updateByXml(new StreamSource(new StringReader(originalConfigXml)));
        }
    }

    private void deleteCreatedJob(Job<?, ?> job) throws IOException, ServletException {
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            job.delete();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServletException("Interrupted while deleting blocked job " + job.getFullName(), e);
        }
    }

    private void restoreSnapshotResult(Snapshot snapshot) {
        if (snapshot.previousResult == null) {
            ScanResultStore.get().remove(snapshot.jobFullName);
            return;
        }
        ScanResultStore.get().put(snapshot.previousResult);
    }

    private void sendBlockedResponse(
            HttpServletRequest request, HttpServletResponse response, RequestTarget target, SecretScanResult result)
            throws IOException {
        String message = enforcementService.buildBlockedMessage(target.actionName, target.jobFullName, result);
        response.reset();
        response.setStatus(target.applyRequest ? HttpServletResponse.SC_OK : HttpServletResponse.SC_CONFLICT);
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(buildBlockedHtml(target, result, message, request.getContextPath()));
    }

    static String buildBlockedHtml(RequestTarget target, SecretScanResult result, String message, String contextPath) {
        String heading = "Secret Guard blocked the change";
        String escapedMessage = Util.xmlEscape(message == null ? "Secret Guard blocked the change." : message);
        String action = Util.xmlEscape(target == null ? "saving" : target.actionName);
        String escapedContextPath = Util.xmlEscape(contextPath == null ? "" : contextPath);
        String stylesheetHref = escapedContextPath + "/plugin/secret-guard/styles/secret-guard.css";
        String jobName = Util.xmlEscape(
                target == null || target.jobFullName == null || target.jobFullName.isBlank()
                        ? "job"
                        : target.jobFullName);
        String ruleId = "n/a";
        String severity = "HIGH";
        String maskedSnippet = "n/a";
        String recommendation = "Move plaintext secrets to Jenkins Credentials and inject them at runtime.";
        String analysisNote = "";
        if (result != null && !result.getFindings().isEmpty()) {
            ruleId = Util.xmlEscape(defaultValue(result.getFindings().get(0).getRuleId(), "n/a"));
            severity = Util.xmlEscape(
                    result.getFindings().get(0).getSeverity() == null
                            ? "HIGH"
                            : result.getFindings().get(0).getSeverity().name());
            maskedSnippet =
                    Util.xmlEscape(defaultValue(result.getFindings().get(0).getMaskedSnippet(), "n/a"));
            recommendation = Util.xmlEscape(defaultValue(
                    result.getFindings().get(0).getRecommendation(),
                    "Move plaintext secrets to Jenkins Credentials and inject them at runtime."));
            analysisNote =
                    Util.xmlEscape(defaultValue(result.getFindings().get(0).getAnalysisNote(), ""));
        }
        return "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
                + "<link rel=\"stylesheet\" href=\"" + stylesheetHref + "\" type=\"text/css\" />"
                + "<title>" + heading + "</title></head><body class=\"secret-guard-blocked-page\">"
                + "<div id=\"error-description\" role=\"alert\" aria-live=\"assertive\" "
                + "class=\"secret-guard-blocked-card\">"
                + "<div class=\"secret-guard-blocked-label\">Error</div>"
                + "<h1 class=\"secret-guard-blocked-title\">" + heading + "</h1>"
                + "<p class=\"secret-guard-blocked-message\">" + escapedMessage + "</p>"
                + "<div class=\"secret-guard-blocked-details\">"
                + "<div class=\"secret-guard-blocked-term\">Action</div><div>" + action + "</div>"
                + "<div class=\"secret-guard-blocked-term\">Job</div><div><code>" + jobName + "</code></div>"
                + "<div class=\"secret-guard-blocked-term\">Rule</div><div><code>" + ruleId + "</code></div>"
                + "<div class=\"secret-guard-blocked-term\">Severity</div><div>" + severity + "</div>"
                + "<div class=\"secret-guard-blocked-term\">Masked snippet</div><div><code>" + maskedSnippet
                + "</code></div>"
                + (analysisNote.isBlank()
                        ? ""
                        : "<div class=\"secret-guard-blocked-term\">Analysis</div><div>" + analysisNote + "</div>")
                + "</div>"
                + "<div class=\"secret-guard-blocked-recommendation\">"
                + "<div class=\"secret-guard-blocked-term secret-guard-blocked-term--stacked\">Recommended fix</div>"
                + "<div>" + recommendation + "</div>"
                + "</div></div></body></html>";
    }

    private static String defaultValue(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static final class Snapshot {
        private final String jobFullName;
        private final String originalConfigXml;
        private final SecretScanResult previousResult;

        private Snapshot(String jobFullName, String originalConfigXml, SecretScanResult previousResult) {
            this.jobFullName = jobFullName;
            this.originalConfigXml = originalConfigXml;
            this.previousResult = previousResult;
        }
    }

    static final class RequestTarget {
        private final String actionName;
        private final String jobFullName;
        private final boolean applyRequest;

        private RequestTarget(String actionName, String jobFullName, boolean applyRequest) {
            this.actionName = actionName;
            this.jobFullName = jobFullName;
            this.applyRequest = applyRequest;
        }

        static RequestTarget from(HttpServletRequest request) {
            String method = request.getMethod();
            if (!"POST".equalsIgnoreCase(method) && !"PUT".equalsIgnoreCase(method)) {
                return null;
            }
            boolean applyRequest = Boolean.parseBoolean(request.getParameter("core:apply"));
            String path = request.getRequestURI();
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isBlank() && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }

            if (path.endsWith("/configSubmit") || path.endsWith("/config.xml")) {
                String fullName = fullNameFromJobPath(path);
                return fullName == null ? null : new RequestTarget("saving", fullName, applyRequest);
            }
            if (path.endsWith("/createItem")) {
                String name = request.getParameter("name");
                if (name == null || name.isBlank()) {
                    return null;
                }
                String parent = fullNameFromJobPath(path.substring(0, path.length() - "/createItem".length()));
                String fullName = parent == null || parent.isBlank() ? name : parent + "/" + name;
                return new RequestTarget("creating", fullName, applyRequest);
            }
            return null;
        }

        Job<?, ?> resolveJob() {
            if (jobFullName == null || jobFullName.isBlank()) {
                return null;
            }
            return Jenkins.get().getItemByFullName(jobFullName, Job.class);
        }

        static String fullNameFromJobPath(String path) {
            List<String> segments = new ArrayList<>();
            String[] tokens = path.split("/");
            for (int index = 0; index < tokens.length - 1; index++) {
                if (!"job".equals(tokens[index])) {
                    continue;
                }
                segments.add(URLDecoder.decode(tokens[index + 1], StandardCharsets.UTF_8));
                index++;
            }
            if (segments.isEmpty()) {
                return null;
            }
            return String.join("/", segments);
        }
    }

    private static final class BufferedResponseWrapper extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final List<Cookie> cookies = new ArrayList<>();
        private final List<Header> headers = new ArrayList<>();

        private ServletOutputStream outputStream;
        private PrintWriter writer;
        private String characterEncoding = StandardCharsets.UTF_8.name();
        private String contentType;
        private int status = HttpServletResponse.SC_OK;
        private String redirectLocation;
        private String errorMessage;

        private BufferedResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        boolean hasFailureStatus() {
            return status >= HttpServletResponse.SC_BAD_REQUEST;
        }

        void commitTo(HttpServletResponse response) throws IOException {
            for (Cookie cookie : cookies) {
                response.addCookie(cookie);
            }
            for (Header header : headers) {
                header.apply(response);
            }
            if (redirectLocation != null) {
                response.sendRedirect(redirectLocation);
                return;
            }
            if (errorMessage != null) {
                response.sendError(status, errorMessage);
                return;
            }
            response.setStatus(status);
            if (contentType != null) {
                response.setContentType(contentType);
            }
            response.setCharacterEncoding(characterEncoding);
            if (writer != null) {
                writer.flush();
            }
            if (outputStream != null) {
                outputStream.flush();
            }
            response.getOutputStream().write(buffer.toByteArray());
        }

        @Override
        public void addCookie(Cookie cookie) {
            cookies.add(cookie);
        }

        @Override
        public void sendError(int sc) {
            status = sc;
        }

        @Override
        public void sendError(int sc, String msg) {
            status = sc;
            errorMessage = msg;
        }

        @Override
        public void sendRedirect(String location) {
            status = HttpServletResponse.SC_FOUND;
            redirectLocation = location;
        }

        @Override
        public void setStatus(int sc) {
            status = sc;
        }

        @Override
        public void setCharacterEncoding(String charset) {
            characterEncoding = charset;
        }

        @Override
        public String getCharacterEncoding() {
            return characterEncoding;
        }

        @Override
        public void setContentType(String type) {
            contentType = type;
        }

        @Override
        public String getContentType() {
            return contentType;
        }

        @Override
        public void setHeader(String name, String value) {
            headers.removeIf(header -> header.name.equalsIgnoreCase(name));
            headers.add(new Header(name, value, true));
        }

        @Override
        public void addHeader(String name, String value) {
            headers.add(new Header(name, value, false));
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (outputStream == null) {
                outputStream = new BufferingServletOutputStream(buffer);
            }
            return outputStream;
        }

        @Override
        public PrintWriter getWriter() {
            if (writer == null) {
                writer = new PrintWriter(new OutputStreamWriter(buffer, StandardCharsets.UTF_8), true);
            }
            return writer;
        }

        @Override
        public void flushBuffer() throws IOException {
            if (writer != null) {
                writer.flush();
            }
            if (outputStream != null) {
                outputStream.flush();
            }
        }
    }

    private record Header(String name, String value, boolean replace) {
        void apply(HttpServletResponse response) {
            if (replace) {
                response.setHeader(name, value);
            } else {
                response.addHeader(name, value);
            }
        }
    }

    private static final class BufferingServletOutputStream extends ServletOutputStream {
        private final ByteArrayOutputStream buffer;

        private BufferingServletOutputStream(ByteArrayOutputStream buffer) {
            this.buffer = buffer;
        }

        @Override
        public void write(int b) {
            buffer.write(b);
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {}
    }
}
