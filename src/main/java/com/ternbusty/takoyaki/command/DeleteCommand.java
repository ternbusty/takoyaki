package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.hooks.Hooks;
import com.ternbusty.takoyaki.ipc.NotifySocket;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

public final class DeleteCommand {
    private DeleteCommand() {}

    public static int run(String rootPath, String containerId, boolean force) {
        if (!State.exists(rootPath, containerId)) {
            if (force) {
                Logger.info("container " + containerId + " does not exist (force)");
                return 0;
            }
            Logger.error("container " + containerId + " does not exist");
            return 1;
        }
        State state;
        try {
            state = State.load(rootPath, containerId).refreshStatus();
        } catch (Exception e) {
            Logger.error("failed to load state: " + e.getMessage());
            return 1;
        }
        if (!state.statusEnum().canDelete()) {
            if (!force) {
                Logger.error("cannot delete container in '" + state.status + "' state (use --force)");
                return 1;
            }
            if (state.pid != null) {
                Libc.kill(state.pid, Constants.SIGKILL);
            }
        }

        try {
            KontainerConfig kc = KontainerConfig.load(rootPath, containerId);
            if (kc.cgroupPath != null) Cgroup.cleanup(kc.cgroupPath);
        } catch (IOException e) {
            Logger.debug("no kontainer config or cgroup cleanup skipped: " + e.getMessage());
        }

        try {
            Files.deleteIfExists(Path.of(NotifySocket.pathFor(containerId)));
        } catch (IOException e) {
            Logger.warn("failed to remove notify socket: " + e.getMessage());
        }

        // poststop hook fires in the runtime namespace before we remove the state dir.
        try {
            Spec spec = Json.readFile(Path.of(state.bundle, "config.json"), Spec::fromJson);
            if (spec.hooks != null) Hooks.run(spec.hooks.poststop, state, "poststop");
        } catch (IOException ignored) {
            // bundle may already be gone for stopped containers; skip silently
        }

        Path dir = State.containerDir(rootPath, containerId);
        try {
            if (Files.exists(dir)) {
                try (Stream<Path> walk = Files.walk(dir)) {
                    walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                    });
                }
            }
            Logger.info("container " + containerId + " deleted");
            return 0;
        } catch (IOException e) {
            Logger.error("failed to delete dir: " + e.getMessage());
            return 1;
        }
    }
}
