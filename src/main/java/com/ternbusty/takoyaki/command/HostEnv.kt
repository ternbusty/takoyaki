package com.ternbusty.takoyaki.command

/** Builds the environment a re-exec'd takoyaki helper process inherits. */
internal object HostEnv {

    /**
     * The current environment minus every `_TAKOYAKI_` control variable.
     * The filter is what keeps internal fd numbers and bootstrap flags from
     * leaking into re-exec'd helpers (and from there into user processes), so
     * every spawn site must build its env through here.
     */
    fun inherited(): MutableList<String> {
        val envList = mutableListOf<String>()
        for ((key, value) in System.getenv()) {
            if (key.startsWith("_TAKOYAKI_")) continue
            envList.add("$key=$value")
        }
        return envList
    }
}
