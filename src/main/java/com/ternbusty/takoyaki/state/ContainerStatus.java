package com.ternbusty.takoyaki.state;

public enum ContainerStatus {
    CREATING("creating"),
    CREATED("created"),
    RUNNING("running"),
    PAUSED("paused"),
    STOPPED("stopped");

    public final String value;

    ContainerStatus(String value) { this.value = value; }

    public boolean canStart() { return this == CREATED; }
    public boolean canKill() { return this == CREATED || this == RUNNING || this == PAUSED; }
    public boolean canDelete() { return this == STOPPED; }

    public static ContainerStatus fromString(String s) {
        for (ContainerStatus cs : values()) {
            if (cs.value.equals(s)) return cs;
        }
        throw new IllegalArgumentException("Unknown status: " + s);
    }
}
