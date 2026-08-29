package com.ternbusty.takoyaki.hooks

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.Json
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Run OCI lifecycle hooks.
 *
 * Each hook is an external command. We pipe the container's current state JSON
 * to the hook's stdin, as required by the OCI runtime spec.
 *
 * The OCI spec distinguishes two hook severities:
 *   - "failable" hooks (prestart, createRuntime, createContainer, startContainer)
 *     MUST abort the lifecycle if they return non-zero. Use [runFailFast].
 *   - post-* hooks (poststart, poststop) are best-effort. A failure is logged
 *     but the lifecycle proceeds. Use [run].
 *
 * The single-method "log warn and continue" we used to have was non-conformant
 * for the failable hooks -- a prestart returning 17 would still let create
 * complete, which violates the spec.
 */
object Hooks {
    /**
     * Run post-* hooks. Failures are logged but never propagate; that's the
     * OCI semantics for poststart / poststop.
     *
     * @return the first error message if any hook failed, null if all succeeded.
     */
    fun run(hooks: List<Spec.Hook>?, state: State, phase: String): String? =
        runEach(hooks, state, phase, failFast = false, processEnv = null)

    /**
     * Run failable hooks (prestart / createRuntime / createContainer /
     * startContainer). The first non-zero exit or timeout aborts the loop
     * and throws -- the caller is expected to surface this as a create/start
     * failure.
     */
    fun runFailFast(hooks: List<Spec.Hook>?, state: State, phase: String): String? =
        runEach(hooks, state, phase, failFast = true, processEnv = null)

    /**
     * Run failable hooks with an inherited process environment. When a hook
     * does not specify its own `env` field, it inherits [processEnv]
     * instead of getting an empty environment. This matches runc's behavior
     * for startContainer hooks, which inherit the container process's env.
     */
    fun runFailFast(
        hooks: List<Spec.Hook>?,
        state: State,
        phase: String,
        processEnv: List<String>?
    ): String? =
        runEach(hooks, state, phase, failFast = true, processEnv = processEnv)

    private fun runEach(
        hooks: List<Spec.Hook>?,
        state: State,
        phase: String,
        failFast: Boolean,
        processEnv: List<String>?
    ): String? {
        if (hooks.isNullOrEmpty()) return null
        var firstError: String? = null
        val stateJson = Json.encode(state.toJson())
        for ((idx, h) in hooks.withIndex()) {
            if (h.path == null) continue
            // runc uses 0-based hook numbering in error messages.
            val hookNum = idx
            val cmd = mutableListOf<String>()
            val hookArgs = h.args
            val hookPath = h.path
            if (!hookArgs.isNullOrEmpty()) {
                // OCI spec: hook.args[0] is the command to execute (like argv[0]);
                // the rest are passed as positional arguments. Unlike the old code
                // that replaced args[0] with h.path, runc uses h.args verbatim.
                cmd.addAll(hookArgs)
            } else {
                cmd.add(hookPath!!)
            }
            val pb = ProcessBuilder(cmd).redirectErrorStream(true)
            // Start from a clean env — inheriting the runtime's env would leak
            // _TAKOYAKI_* variables into the hook.
            pb.environment().clear()
            if (h.env != null) {
                // Hook specifies its own env: use exactly that.
                for (e in h.env) {
                    val eq = e.indexOf('=')
                    if (eq > 0) pb.environment()[e.substring(0, eq)] = e.substring(eq + 1)
                }
            } else if (processEnv != null) {
                // No hook env but a process env was provided (startContainer):
                // inherit the container process's environment, matching runc.
                for (e in processEnv) {
                    val eq = e.indexOf('=')
                    if (eq > 0) pb.environment()[e.substring(0, eq)] = e.substring(eq + 1)
                }
            }
            try {
                val p = pb.start()
                // Pipe the state JSON to stdin. Hooks that exit without reading
                // (e.g. /bin/true) cause EPIPE on write or on the implicit
                // flush during close; catch both to avoid false failures.
                try {
                    val stdin = p.outputStream
                    stdin.write(stateJson.toByteArray())
                    stdin.close()
                } catch (_: IOException) {
                    // Broken pipe: the hook exited before reading all of stdin.
                }
                val timeout = h.timeout?.toLong() ?: 30L
                val done = p.waitFor(timeout, TimeUnit.SECONDS)
                if (!done) {
                    p.destroyForcibly()
                    // runc format: "error running <phase> hook #<n>: ..."
                    val msg = "error running $phase hook #$hookNum" +
                        ": hook did not complete within ${timeout}s"
                    if (failFast) throw RuntimeException(msg)
                    if (firstError == null) firstError = msg
                    Logger.warn(msg)
                    continue
                }
                val rc = p.exitValue()
                if (rc != 0) {
                    // Capture stderr/stdout from the hook for the error message.
                    val hookOutput = try {
                        String(p.inputStream.readAllBytes()).trim()
                    } catch (_: IOException) {
                        ""
                    }
                    val exitDesc = describeExit(rc)
                    val detail = if (hookOutput.isEmpty()) exitDesc
                    else "$hookOutput: $exitDesc"
                    val msg = "error running $phase hook #$hookNum: $detail"
                    if (failFast) throw RuntimeException(msg)
                    if (firstError == null) firstError = msg
                    Logger.warn(msg)
                } else {
                    Logger.debug("hook $phase ${h.path} ok")
                }
            } catch (e: IOException) {
                val msg = "error running $phase hook #$hookNum: ${e.message}"
                if (failFast) throw RuntimeException(msg, e)
                if (firstError == null) firstError = msg
                Logger.warn(msg)
            } catch (e: InterruptedException) {
                val msg = "error running $phase hook #$hookNum: ${e.message}"
                if (failFast) throw RuntimeException(msg, e)
                if (firstError == null) firstError = msg
                Logger.warn(msg)
            }
        }
        return firstError
    }

    /**
     * Describe a process exit code the way Go does: if the process was killed
     * by a signal (exit code > 128), produce "signal: <name>" instead of
     * "exit status <code>". runc's bats tests rely on matching "bad system call"
     * when a hook is killed by SIGSYS.
     */
    private fun describeExit(rc: Int): String {
        if (rc > 128) {
            val sig = rc - 128
            val name = signalName(sig)
            if (name != null) return "signal: $name"
        }
        return "exit status $rc"
    }

    private fun signalName(sig: Int): String? = when (sig) {
        1 -> "hangup"
        2 -> "interrupt"
        3 -> "quit"
        4 -> "illegal instruction"
        5 -> "trace/breakpoint trap"
        6 -> "aborted"
        7 -> "bus error"
        8 -> "floating point exception"
        9 -> "killed"
        11 -> "segmentation fault"
        13 -> "broken pipe"
        14 -> "alarm clock"
        15 -> "terminated"
        31 -> "bad system call"
        else -> null
    }
}
