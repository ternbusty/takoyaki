package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;

public final class ResumeCommand {
    private ResumeCommand() {}

    public static int run(String rootPath, String containerId) {
        try {
            State state = State.load(rootPath, containerId).refreshStatus();
            if (state.statusEnum() != ContainerStatus.RUNNING
                    && state.statusEnum() != ContainerStatus.PAUSED) {
                System.err.println("cannot resume container " + containerId
                        + " that is not paused");
                return 1;
            }
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        return Freeze.write(rootPath, containerId, "0", "resume");
    }
}
