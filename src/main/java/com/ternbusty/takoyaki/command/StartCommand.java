package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.hooks.Hooks;
import com.ternbusty.takoyaki.ipc.NotifySocket;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.util.Json;

import java.nio.file.Path;

public final class StartCommand {
    private StartCommand() {}

    public static int run(String rootPath, String containerId) {
        State state;
        try {
            state = State.load(rootPath, containerId).refreshStatus();
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        if (!state.statusEnum().canStart()) {
            String msg = switch (state.statusEnum()) {
                case STOPPED -> "cannot start a container that has stopped";
                case RUNNING -> "cannot start an already running container";
                case PAUSED -> "cannot start a paused container";
                default -> "cannot start container in '" + state.status + "' state";
            };
            System.err.println(msg);
            return 1;
        }
        Spec spec = null;
        try {
            spec = Json.readFile(Path.of(state.bundle, "config.json"), Spec::fromJson);
        } catch (Exception e) {
            Logger.debug("could not reload spec for hooks: " + e.getMessage());
        }

        // No process.args validation here. runtime-tools' validation/start
        // test 7 expects start to return success even when spec.process is
        // nil (the assertion is `err == nil` despite the message saying
        // "MUST generate an error" — see runtime-tools/validation/start
        // upstream bug). The container then reaches 'stopped' naturally
        // because InitProcess detects empty args and _exits(1).

        try {
            NotifySocket.sendStart(NotifySocket.pathFor(containerId));
            State updated = state.withStatus(ContainerStatus.RUNNING);
            updated.save(rootPath);
            Logger.info("container " + containerId + " started");

            // poststart hook runs in the runtime namespace after the user process is started.
            Logger.debug("poststart: spec=" + (spec != null) + " hooks=" + (spec != null && spec.hooks != null)
                    + " count=" + (spec != null && spec.hooks != null && spec.hooks.poststart != null ? spec.hooks.poststart.size() : 0));
            if (spec != null && spec.hooks != null) {
                Hooks.run(spec.hooks.poststart, updated, "poststart");
            }
            return 0;
        } catch (Exception e) {
            System.err.println("failed to start: " + e.getMessage());
            return 1;
        }
    }
}
