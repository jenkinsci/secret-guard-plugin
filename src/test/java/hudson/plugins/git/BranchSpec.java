package hudson.plugins.git;

public class BranchSpec {
    private String name;

    public BranchSpec() {}

    public BranchSpec(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
