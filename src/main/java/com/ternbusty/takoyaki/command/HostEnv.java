package com.ternbusty.takoyaki.command;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Builds the environment a re-exec'd takoyaki helper process inherits. */
final class HostEnv {
    private HostEnv() {}

    /**
     * The current environment minus every {@code _TAKOYAKI_} control variable.
     * The filter is what keeps internal fd numbers and bootstrap flags from
     * leaking into re-exec'd helpers (and from there into user processes), so
     * every spawn site must build its env through here.
     */
    static List<String> inherited() {
        List<String> envList = new ArrayList<>();
        for (Map.Entry<String, String> e : System.getenv().entrySet()) {
            if (e.getKey().startsWith("_TAKOYAKI_")) continue;
            envList.add(e.getKey() + "=" + e.getValue());
        }
        return envList;
    }
}
