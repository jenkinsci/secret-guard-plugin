package hudson.plugins.git;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.scm.NullSCM;
import hudson.scm.SCMRevisionState;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GitSCM extends NullSCM {
    private List<BranchSpec> branches = new ArrayList<>();
    private Map<String, Map<String, String>> filesByBranch = new LinkedHashMap<>();

    public GitSCM() {}

    public GitSCM(List<BranchSpec> branches, Map<String, Map<String, String>> filesByBranch) {
        this.branches = new ArrayList<>(branches);
        this.filesByBranch = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, String>> entry : filesByBranch.entrySet()) {
            this.filesByBranch.put(entry.getKey(), new LinkedHashMap<>(entry.getValue()));
        }
    }

    public List<BranchSpec> getBranches() {
        return branches;
    }

    public Map<String, String> filesForBranch(String branchName) {
        return filesByBranch.getOrDefault(branchName, Map.of());
    }

    @Override
    public void checkout(
            Run<?, ?> build,
            Launcher launcher,
            FilePath workspace,
            TaskListener listener,
            File changelogFile,
            SCMRevisionState baseline)
            throws IOException, InterruptedException {
        for (Map<String, String> files : filesByBranch.values()) {
            for (Map.Entry<String, String> entry : files.entrySet()) {
                workspace.child(entry.getKey()).write(entry.getValue(), StandardCharsets.UTF_8.name());
            }
        }
    }
}
