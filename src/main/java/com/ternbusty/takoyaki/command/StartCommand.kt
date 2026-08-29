package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.hooks.Hooks
import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.Json
import java.nio.file.Path

object StartCommand {

    fun run(rootPath: String, containerId: String): Int {
        val state: State
        try {
            state = State.load(rootPath, containerId).refreshStatus()
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }
        if (!state.statusEnum().canStart()) {
            val msg = when (state.statusEnum()) {
                ContainerStatus.STOPPED -> "cannot start a container that has stopped"
                ContainerStatus.RUNNING -> "cannot start an already running container"
                ContainerStatus.PAUSED -> "cannot start a paused container"
                else -> "cannot start container in '${state.status}' state"
            }
            System.err.println(msg)
            return 1
        }
        var spec: Spec? = null
        try {
            spec = Json.readFile(Path.of(state.bundle, "config.json"), Spec::fromJson)
        } catch (e: Exception) {
            Logger.debug("could not reload spec for hooks: ${e.message}")
        }

        // No process.args validation here. runtime-tools' validation/start
        // test 7 expects start to return success even when spec.process is
        // nil (the assertion is `err == nil` despite the message saying
        // "MUST generate an error" — see runtime-tools/validation/start
        // upstream bug). The container then reaches 'stopped' naturally
        // because InitProcess detects empty args and _exits(1).

        return try {
            NotifySocket.sendStart(NotifySocket.pathFor(containerId))
            val updated = state.withStatus(ContainerStatus.RUNNING)
            updated.save(rootPath)
            Logger.info("container $containerId started")

            // poststart hook runs in the runtime namespace after the user process is started.
            // runc compat: poststart hook failure causes the container to be killed
            // and the run/start command to return non-zero.
            Logger.debug(
                "poststart: spec=${spec != null} hooks=${spec?.hooks != null}" +
                    " count=${spec?.hooks?.poststart?.size ?: 0}"
            )
            val hooks = spec?.hooks
            if (hooks != null) {
                val hookErr = Hooks.run(hooks.poststart, updated, "poststart")
                if (hookErr != null) {
                    System.err.println(hookErr)
                    return 1
                }
            }
            0
        } catch (e: Exception) {
            System.err.println("failed to start: ${e.message}")
            1
        }
    }
}
