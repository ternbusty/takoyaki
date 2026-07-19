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
        runEach(hooks, state, phase, false);
    }

    /**
     * Run failable hooks (prestart / createRuntime / createContainer /
     * startContainer). The first non-zero exit or timeout aborts the loop
     * and throws — the caller is expected to surface this as a create/start
     * failure.
     */
    public static void runFailFast(List<Spec.Hook> hooks, State state, String phase) {
        runEach(hooks, state, phase, true);
    }

    private static void runEach(List<Spec.Hook> hooks, State state, String phase,
                                boolean failFast) {
        if (hooks == null || hooks.isEmpty()) return;
        String stateJson = Json.encode(state.toJson());
        for (Spec.Hook h : hooks) {
            if (h.path == null) continue;
            List<String> cmd = new ArrayList<>();
            cmd.add(h.path);
            if (h.args != null) cmd.addAll(h.args.subList(1, h.args.size()));
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
            // Always start from a clean env — inheriting the runtime's env
            // would leak whatever _TAKOYAKI_* variables and container-id state
            // the caller had into the hook, which is surprising and defeats
            // the point of the spec's env field. If the spec left env unset
            // the hook gets an empty env; if it's set we use exactly that.
            // Matches youki (env_clear + envs).
            pb.environment().clear();
            if (h.env != null) {
                for (String e : h.env) {
                    int eq = e.indexOf('=');
                    if (eq > 0) pb.environment().put(e.substring(0, eq), e.substring(eq + 1));
                }
            }
            try {
                Process p = pb.start();
                try (OutputStream stdin = p.getOutputStream()) {
                    stdin.write(stateJson.getBytes());
                }
                long timeout = h.timeout == null ? 30 : h.timeout;
                boolean done = p.waitFor(timeout, TimeUnit.SECONDS);
                if (!done) {
                    p.destroyForcibly();
                    String msg = "hook " + phase + " " + h.path + " timeout after " + timeout + "s";
                    if (failFast) throw new RuntimeException(msg);
                    Logger.warn(msg);
                    continue;
                }
                int rc = p.exitValue();
                if (rc != 0) {
                    String msg = "hook " + phase + " " + h.path + " exit=" + rc;
                    if (failFast) throw new RuntimeException(msg);
                    Logger.warn(msg);
                } else {
                    Logger.debug("hook " + phase + " " + h.path + " ok");
                }
            } catch (IOException | InterruptedException e) {
                String msg = "hook " + phase + " " + h.path + " failed: " + e.getMessage();
                if (failFast) throw new RuntimeException(msg, e);
                Logger.warn(msg);
            }
        }
    }
}
