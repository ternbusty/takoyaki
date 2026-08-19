package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.State;

/**
 * runc-compatible foreground lifecycle in one process: create + start + wait + delete.
 *
 * <p>The benefit over {@code takoyaki create && start && delete} from a shell loop is
 * that the binary is exec'd once instead of three times. On a cold page cache, that
 * saves roughly 2x the binary-mmap cost (~60 ms in our benchmarks). On a warm cache
 * the wins are smaller but real because each exec also re-runs the bootstrap.c
 * constructor and SubstrateVM Isolate startup.
 *
 * <p>The wait step relies on stage2 being a direct child of this process via
 * {@code CLONE_PARENT} in bootstrap.c — so {@link Wait#waitForChild} succeeds.
 *
 * <p>With {@code --detach} we behave like {@code create + start}, returning right
 * after start emits the START signal. No wait, no delete; the caller is
 * responsible for cleanup. runc and youki use the same convention.
 */
public final class RunCommand {
    private RunCommand() {}

    public static int run(String rootPath, boolean debug, String containerId,
                          String bundleIn, String pidFile, String consoleSocket,
                          boolean noPivot, boolean noNewKeyring, int preserveFds,
                          boolean detach) {
        int rc = CreateCommand.run(rootPath, debug, containerId, bundleIn,
                pidFile, consoleSocket, noPivot, noNewKeyring, preserveFds);
        if (rc != 0) return rc;

        if (detach) {
            return StartCommand.run(rootPath, containerId);
        }

        // Foreground path. Snapshot the init pid BEFORE start because the
        // container can race to "stopped" and have its state torn down if
        // process.args is trivial (e.g. /bin/echo).
        int initPid;
        try {
            State st = State.load(rootPath, containerId);
            initPid = st.pid != null ? st.pid : 0;
        } catch (Exception e) {
            System.err.println("failed to load state after create: " + e.getMessage());
            DeleteCommand.run(rootPath, containerId, true);
            return 1;
        }

        rc = StartCommand.run(rootPath, containerId);
        if (rc != 0) {
            // Best-effort cleanup. Force because the container may be in a
            // partial state that canDelete rejects.
            DeleteCommand.run(rootPath, containerId, true);
            return rc;
        }

        int exitCode = 0;
        if (initPid > 0) {
            // Blocks until stage2 exits. Stage2 is our direct child because
            // bootstrap.c clones it with CLONE_PARENT. The returned status is
            // already shell-style (WEXITSTATUS for normal exit, 128+sig for
            // signal termination).
            exitCode = Wait.waitForChild(initPid);
        }

        // Force delete: the container is now stopped (we just waited), so the
        // non-force path would also work, but force is safer if waitpid raced
        // (e.g. ECHILD because someone else already reaped).
        DeleteCommand.run(rootPath, containerId, true);
        return exitCode;
    }
}
