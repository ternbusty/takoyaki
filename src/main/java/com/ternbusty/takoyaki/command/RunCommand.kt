package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.console.InternalConsole
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.JsonCodec
import java.nio.file.Path

/**
 * runc-compatible foreground lifecycle in one process: create + start + wait + delete.
 *
 * The benefit over `takoyaki create && start && delete` from a shell loop is
 * that the binary is exec'd once instead of three times. On a cold page cache, that
 * saves roughly 2x the binary-mmap cost (~60 ms in our benchmarks). On a warm cache
 * the wins are smaller but real because each exec also re-runs the bootstrap.c
 * constructor and SubstrateVM Isolate startup.
 *
 * The wait step relies on stage2 being a direct child of this process via
 * `CLONE_PARENT` in bootstrap.c -- so [Wait.waitForChild] succeeds.
 *
 * With `--detach` we behave like `create + start`, returning right
 * after start emits the START signal. No wait, no delete; the caller is
 * responsible for cleanup. runc and youki use the same convention.
 */
object RunCommand {

    fun run(
        rootPath: String,
        debug: Boolean,
        containerId: String,
        bundleIn: String,
        pidFile: String?,
        consoleSocket: String?,
        noPivot: Boolean,
        noNewKeyring: Boolean,
        preserveFds: Int,
        detach: Boolean,
        pidfdSocket: String?,
    ): Int {
        // For foreground runs with terminal=true and no --console-socket, create
        // an internal PTY proxy so the container's stdio flows through a real
        // pseudoterminal (matching runc behaviour).
        var internalConsole: InternalConsole? = null
        var effectiveConsoleSocket = consoleSocket
        if (!detach && consoleSocket == null) {
            try {
                val bundle = Path.of(bundleIn).toAbsolutePath().normalize().toString()
                val spec = JsonCodec.loadFromFile<Spec>(Path.of(bundle, "config.json"))
                if (spec?.process?.terminal == true) {
                    internalConsole = InternalConsole.createForRun(bundle)
                    internalConsole.startListening()
                    effectiveConsoleSocket = internalConsole.socketPath
                    Logger.debug("internal console socket at $effectiveConsoleSocket")
                }
            } catch (e: Exception) {
                // Config parse will be retried by CreateCommand; just skip internal console.
                Logger.debug("skipping internal console: ${e.message}")
            }
        }

        var rc = CreateCommand.run(
            rootPath, debug, containerId, bundleIn,
            pidFile, effectiveConsoleSocket, noPivot, noNewKeyring, preserveFds,
            pidfdSocket
        )
        if (rc != 0) {
            internalConsole?.stop()
            return rc
        }

        if (detach) {
            internalConsole?.stop()
            return StartCommand.run(rootPath, containerId)
        }

        // Wait for the listener thread to receive the master fd from init.
        internalConsole?.apply {
            awaitMaster(10_000)
            startIOCopy()
        }

        // Foreground path. Snapshot the init pid BEFORE start because the
        // container can race to "stopped" and have its state torn down if
        // process.args is trivial (e.g. /bin/echo).
        val initPid: Int
        try {
            val st = State.load(rootPath, containerId)
            initPid = st.pid ?: 0
        } catch (e: Exception) {
            System.err.println("failed to load state after create: ${e.message}")
            internalConsole?.stop()
            DeleteCommand.run(rootPath, containerId, true)
            return 1
        }

        rc = StartCommand.run(rootPath, containerId)
        if (rc != 0) {
            // Best-effort cleanup. Force because the container may be in a
            // partial state that canDelete rejects.
            internalConsole?.stop()
            DeleteCommand.run(rootPath, containerId, true)
            return rc
        }

        var exitCode = 0
        if (initPid > 0) {
            // Blocks until stage2 exits. Stage2 is our direct child because
            // bootstrap.c clones it with CLONE_PARENT. The returned status is
            // already shell-style (WEXITSTATUS for normal exit, 128+sig for
            // signal termination).
            exitCode = Wait.waitForChild(initPid)
        }

        internalConsole?.stop()

        // Force delete: the container is now stopped (we just waited), so the
        // non-force path would also work, but force is safer if waitpid raced
        // (e.g. ECHILD because someone else already reaped).
        DeleteCommand.run(rootPath, containerId, true)
        return exitCode
    }
}
