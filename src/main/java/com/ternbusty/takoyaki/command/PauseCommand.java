package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;

public final class PauseCommand {
    private PauseCommand() {}

    public static int run(String rootPath, String containerId) {
        try {
            State state = State.load(rootPath, containerId).refreshStatus();
            if (state.statusEnum() != ContainerStatus.RUNNING) {
                System.err.println("cannot pause container " + containerId
                        + " that is not running");
                return 1;
            }
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        return Freeze.write(rootPath, containerId, "1", "pause");
    }
}
