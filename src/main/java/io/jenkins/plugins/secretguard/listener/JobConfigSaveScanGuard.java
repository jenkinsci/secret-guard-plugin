package io.jenkins.plugins.secretguard.listener;

final class JobConfigSaveScanGuard {
    private static final ThreadLocal<Integer> FILTER_MANAGED_SAVE_DEPTH = ThreadLocal.withInitial(() -> 0);

    private JobConfigSaveScanGuard() {}

    static Scope filterManagedSave() {
        FILTER_MANAGED_SAVE_DEPTH.set(FILTER_MANAGED_SAVE_DEPTH.get() + 1);
        return new Scope();
    }

    static boolean isFilterManagedSave() {
        return FILTER_MANAGED_SAVE_DEPTH.get() > 0;
    }

    static final class Scope implements AutoCloseable {
        private boolean closed;

        @Override
        public void close() {
            if (closed) {
                return;
            }
            int depth = FILTER_MANAGED_SAVE_DEPTH.get();
            if (depth <= 1) {
                FILTER_MANAGED_SAVE_DEPTH.remove();
            } else {
                FILTER_MANAGED_SAVE_DEPTH.set(depth - 1);
            }
            closed = true;
        }
    }
}
