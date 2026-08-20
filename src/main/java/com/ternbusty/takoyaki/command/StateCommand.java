package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.util.Json;

public final class StateCommand {
    private StateCommand() {}

    public static int run(String rootPath, String containerId) {
        try {
            State s = State.load(rootPath, containerId).refreshStatus();
            System.out.println(Json.encode(s.toJson()));
            return 0;
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
    }
}
