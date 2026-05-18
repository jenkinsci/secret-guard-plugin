package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.plugins.git.BranchSpec;
import hudson.plugins.git.GitSCM;
import hudson.scm.NullSCM;
import hudson.scm.SCM;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ScmJenkinsfileReaderTest {
    private final ScmJenkinsfileReader reader = new ScmJenkinsfileReader();

    @Test
    void normalizesLiteralGitBranchSpecToRefsHeads() throws Exception {
        assertEquals("refs/heads/release/1.1", invokeNormalizeGitBranchSpec("release/1.1"));
        assertEquals("main", invokeNormalizeGitBranchSpec("main"));
    }

    @Test
    void leavesSupportedAndParameterizedGitBranchSpecsUnchanged() throws Exception {
        assertEquals("refs/heads/release/1.1", invokeNormalizeGitBranchSpec("refs/heads/release/1.1"));
        assertEquals("refs/tags/v1.0.0", invokeNormalizeGitBranchSpec("refs/tags/v1.0.0"));
        assertEquals("*/release/1.1", invokeNormalizeGitBranchSpec("*/release/1.1"));
        assertEquals("release/*", invokeNormalizeGitBranchSpec("release/*"));
        assertEquals("release/?", invokeNormalizeGitBranchSpec("release/?"));
        assertEquals("${BRANCH}", invokeNormalizeGitBranchSpec("${BRANCH}"));
        assertEquals("origin/@{1}", invokeNormalizeGitBranchSpec("origin/@{1}"));
        assertEquals("", invokeNormalizeGitBranchSpec(null));
        assertEquals("", invokeNormalizeGitBranchSpec("   "));
    }

    @Test
    void normalizesGitScmCloneWhenLiteralBranchNeedsFallback() throws Exception {
        GitSCM original = new GitSCM(List.of(new BranchSpec("release/1.1")), Map.of());

        Optional<?> normalization = invokeNormalizeGitScmForLightweight(original);

        assertTrue(normalization.isPresent());
        Object result = normalization.orElseThrow();
        SCM normalizedScm = (SCM) invokeNoArg(result, "scm");
        String normalizedBranch = (String) invokeNoArg(result, "normalizedBranch");

        assertEquals("refs/heads/release/1.1", normalizedBranch);
        assertInstanceOf(GitSCM.class, normalizedScm);
        assertEquals("release/1.1", original.getBranches().get(0).getName());
        assertEquals(
                "refs/heads/release/1.1",
                ((GitSCM) normalizedScm).getBranches().get(0).getName());
    }

    @Test
    void skipsNormalizationForUnsupportedGitFallbackShapes() throws Exception {
        assertTrue(invokeNormalizeGitScmForLightweight(new NullSCM()).isEmpty());
        assertTrue(invokeNormalizeGitScmForLightweight(
                        new GitSCM(List.of(new BranchSpec("refs/heads/release/1.1")), Map.of()))
                .isEmpty());
        assertTrue(invokeNormalizeGitScmForLightweight(new GitSCM(List.of(new BranchSpec("${BRANCH}")), Map.of()))
                .isEmpty());
        assertTrue(invokeNormalizeGitScmForLightweight(
                        new GitSCM(List.of(new BranchSpec("release/1.1"), new BranchSpec("release/1.2")), Map.of()))
                .isEmpty());
    }

    @Test
    void rebuildGitScmWithNormalizedBranchReturnsEmptyWhenOriginalBranchDoesNotMatch() throws Exception {
        GitSCM scm = new GitSCM(List.of(new BranchSpec("main")), Map.of());

        Optional<?> rebuilt = invokeRebuildGitScmWithNormalizedBranch(scm, "release/1.1", "refs/heads/release/1.1");

        assertFalse(rebuilt.isPresent());
    }

    @Test
    void readBranchesReturnsEmptyListWhenMethodResultIsNotAList() throws Exception {
        @SuppressWarnings("deprecation")
        SCM scm = new NonListBranchesScm();

        List<?> branches = invokeReadBranches(scm);

        assertTrue(branches.isEmpty());
    }

    @Test
    void readBranchNameReturnsEmptyStringWhenMethodResultIsNotAString() throws Exception {
        String branchName = invokeReadBranchName(new NonStringBranchSpec());

        assertEquals("", branchName);
    }

    @Test
    void updateBranchNameMutatesSuperclassField() throws Exception {
        DerivedNamedBranchSpec branchSpec = new DerivedNamedBranchSpec();

        invokeUpdateBranchName(branchSpec, "refs/heads/release/1.1");

        assertEquals("refs/heads/release/1.1", branchSpec.getName());
    }

    @Test
    void updateBranchNameFailsWhenNoNameFieldExists() {
        InvocationTargetException error = assertThrows(
                InvocationTargetException.class, () -> invokeUpdateBranchName(new NoNameBranchSpec(), "refs/heads/x"));

        assertInstanceOf(NoSuchFieldException.class, error.getCause());
    }

    @Test
    void findFieldSearchesSuperclassesAndReturnsNullWhenMissing() throws Exception {
        Field inherited = invokeFindField(DerivedNamedBranchSpec.class, "name");
        Field missing = invokeFindField(DerivedNamedBranchSpec.class, "missing");

        assertNotNull(inherited);
        assertEquals("name", inherited.getName());
        assertEquals(null, missing);
    }

    @Test
    void normalizeScriptPathDefaultsAndTrimsLeadingSlash() throws Exception {
        assertEquals("Jenkinsfile", invokeNormalizeScriptPath(null));
        assertEquals("Jenkinsfile", invokeNormalizeScriptPath("   "));
        assertEquals("ci/Jenkinsfile", invokeNormalizeScriptPath(" /ci/Jenkinsfile "));
    }

    private String invokeNormalizeGitBranchSpec(String branchName) throws Exception {
        return (String) invoke(reader, "normalizeGitBranchSpec", new Class<?>[] {String.class}, branchName);
    }

    @SuppressWarnings("unchecked")
    private Optional<?> invokeNormalizeGitScmForLightweight(SCM scm) throws Exception {
        return (Optional<?>) invoke(reader, "normalizeGitScmForLightweight", new Class<?>[] {SCM.class}, scm);
    }

    @SuppressWarnings("unchecked")
    private Optional<?> invokeRebuildGitScmWithNormalizedBranch(SCM scm, String originalBranch, String normalizedBranch)
            throws Exception {
        return (Optional<?>) invoke(
                reader,
                "rebuildGitScmWithNormalizedBranch",
                new Class<?>[] {SCM.class, String.class, String.class},
                scm,
                originalBranch,
                normalizedBranch);
    }

    @SuppressWarnings("unchecked")
    private List<?> invokeReadBranches(SCM scm) throws Exception {
        return (List<?>) invoke(reader, "readBranches", new Class<?>[] {SCM.class}, scm);
    }

    private String invokeReadBranchName(Object branchSpec) throws Exception {
        return (String) invoke(reader, "readBranchName", new Class<?>[] {Object.class}, branchSpec);
    }

    private void invokeUpdateBranchName(Object branchSpec, String branchName) throws Exception {
        invoke(reader, "updateBranchName", new Class<?>[] {Object.class, String.class}, branchSpec, branchName);
    }

    private Field invokeFindField(Class<?> type, String name) throws Exception {
        return (Field) invoke(reader, "findField", new Class<?>[] {Class.class, String.class}, type, name);
    }

    private String invokeNormalizeScriptPath(String path) throws Exception {
        return (String) invoke(reader, "normalizeScriptPath", new Class<?>[] {String.class}, path);
    }

    private Object invokeNoArg(Object target, String methodName) throws Exception {
        Method method = target.getClass().getDeclaredMethod(methodName);
        method.setAccessible(true);
        return method.invoke(target);
    }

    private Object invoke(Object target, String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = target.getClass().getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return method.invoke(target, args);
    }

    private static class NonListBranchesScm extends NullSCM {
        public String getBranches() {
            return "not-a-list";
        }
    }

    private static class NonStringBranchSpec {
        public Integer getName() {
            return 7;
        }
    }

    private static class BaseNamedBranchSpec {
        private String name = "release/1.1";

        String getName() {
            return name;
        }
    }

    private static class DerivedNamedBranchSpec extends BaseNamedBranchSpec {}

    private static class NoNameBranchSpec {}
}
