package com.ternbusty.takoyaki.hooks;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Run OCI lifecycle hooks.
 *
 * Each hook is an external command. We pipe the container's current state JSON
 * to the hook's stdin, as required by the OCI runtime spec.
 *
 * The OCI spec distinguishes two hook severities:
 *   - "failable" hooks (prestart, createRuntime, createContainer, startContainer)
 *     MUST abort the lifecycle if they return non-zero. Use {@link #runFailFast}.
 *   - post-* hooks (poststart, poststop) are best-effort. A failure is logged
 *     but the lifecycle proceeds. Use {@link #run}.
 *
 * The single-method "log warn and continue" we used to have was non-conformant
 * for the failable hooks — a prestart returning 17 would still let create
 * complete, which violates the spec.
 */
public final class Hooks {
    private Hooks() {}

    /**
     * Run post-* hooks. Failures are logged but never propagate; that's the
     * OCI semantics for poststart / poststop.
     */
    public static void run(List<Spec.Hook> hooks, State state, String phase) {
        runEach(hooks, state, phase, false, null);
    }

    /**
     * Run failable hooks (prestart / createRuntime / createContainer /
     * startContainer). The first non-zero exit or timeout aborts the loop
     * and throws — the caller is expected to surface this as a create/start
     * failure.
     */
    public static void runFailFast(List<Spec.Hook> hooks, State state, String phase) {
        runEach(hooks, state, phase, true, null);
    }

    /**
     * Run failable hooks with an inherited process environment. When a hook
     * does not specify its own {@code env} field, it inherits {@code processEnv}
     * instead of getting an empty environment. This matches runc's behavior
     * for startContainer hooks, which inherit the container process's env.
     */
    public static void runFailFast(List<Spec.Hook> hooks, State state, String phase,
                                   List<String> processEnv) {
        runEach(hooks, state, phase, true, processEnv);
    }

    private static void runEach(List<Spec.Hook> hooks, State state, String phase,
                                boolean failFast, List<String> processEnv) {
        if (hooks == null || hooks.isEmpty()) return;
        String stateJson = Json.encode(state.toJson());
        for (int idx = 0; idx < hooks.size(); idx++) {
            Spec.Hook h = hooks.get(idx);
            if (h.path == null) continue;
            // runc uses 0-based hook numbering in error messages.
            int hookNum = idx;
            List<String> cmd = new ArrayList<>();
            if (h.args != null && !h.args.isEmpty()) {
                // OCI spec: hook.args[0] is the command to execute (like argv[0]);
                // the rest are passed as positional arguments. Unlike the old code
                // that replaced args[0] with h.path, runc uses h.args verbatim.
                cmd.addAll(h.args);
            } else {
                cmd.add(h.path);
            }
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
            // Start from a clean env — inheriting the runtime's env would leak
            // _TAKOYAKI_* variables into the hook.
            pb.environment().clear();
            if (h.env != null) {
                // Hook specifies its own env: use exactly that.
                for (String e : h.env) {
                    int eq = e.indexOf('=');
                    if (eq > 0) pb.environment().put(e.substring(0, eq), e.substring(eq + 1));
                }
            } else if (processEnv != null) {
                // No hook env but a process env was provided (startContainer):
                // inherit the container process's environment, matching runc.
                for (String e : processEnv) {
                    int eq = e.indexOf('=');
                    if (eq > 0) pb.environment().put(e.substring(0, eq), e.substring(eq + 1));
                }
            }
            try {
                Process p = pb.start();
                // Pipe the state JSON to stdin. Hooks that exit without reading
                // (e.g. /bin/true) cause EPIPE on write or on the implicit
                // flush during close; catch both to avoid false failures.
                try {
                    OutputStream stdin = p.getOutputStream();
                    stdin.write(stateJson.getBytes());
                    stdin.close();
                } catch (IOException ignored) {
                    // Broken pipe: the hook exited before reading all of stdin.
                }
                long timeout = h.timeout == null ? 30 : h.timeout;
                boolean done = p.waitFor(timeout, TimeUnit.SECONDS);
                if (!done) {
                    p.destroyForcibly();
                    // runc format: "error running <phase> hook #<n>: ..."
                    String msg = "error running " + phase + " hook #" + hookNum
                            + ": hook did not complete within " + timeout + "s";
                    if (failFast) throw new RuntimeException(msg);
                    Logger.warn(msg);
                    continue;
                }
                int rc = p.exitValue();
                if (rc != 0) {
                    // Capture stderr/stdout from the hook for the error message.
                    String hookOutput = "";
                    try {
                        hookOutput = new String(p.getInputStream().readAllBytes()).trim();
                    } catch (IOException ignored) {}
                    String detail = hookOutput.isEmpty()
                            ? "exit status " + rc
                            : hookOutput + ": exit status " + rc;
                    String msg = "error running " + phase + " hook #" + hookNum
                            + ": " + detail;
                    if (failFast) throw new RuntimeException(msg);
                    Logger.warn(msg);
                } else {
                    Logger.debug("hook " + phase + " " + h.path + " ok");
                }
            } catch (IOException | InterruptedException e) {
                String msg = "error running " + phase + " hook #" + hookNum
                        + ": " + e.getMessage();
                if (failFast) throw new RuntimeException(msg, e);
                Logger.warn(msg);
            }
        }
    }
}
