package com.ternbusty.takoyaki.state

enum class ContainerStatus(val value: String) {
    CREATING("creating"),
    CREATED("created"),
    RUNNING("running"),
    PAUSED("paused"),
    STOPPED("stopped");

    fun canStart(): Boolean = this == CREATED
    fun canKill(): Boolean = this == CREATED || this == RUNNING || this == PAUSED
    fun canDelete(): Boolean = this == STOPPED

    companion object {
        fun fromString(s: String): ContainerStatus =
            entries.firstOrNull { it.value == s }
                ?: throw IllegalArgumentException("Unknown status: $s")
    }
}
