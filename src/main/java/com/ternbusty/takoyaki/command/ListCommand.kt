package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.JsonCodec
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

object ListCommand {

    fun run(rootPath: String, format: String?, quiet: Boolean): Int {
        val rootDir = Path.of(rootPath)
        if (!Files.isDirectory(rootDir)) {
            // runc behaviour: `list` with the default root succeeds even when
            // the directory does not exist yet (no containers have been
            // created). But if the user passed an explicit --root that does not
            // exist, return an error.
            if (isDefaultRoot(rootPath)) {
                if (format == "json") println("[]")
                return 0
            }
            System.err.println("\"$rootPath\" does not exist")
            return 1
        }
        val states = mutableListOf<State>()
        try {
            Files.newDirectoryStream(rootDir).use { ds ->
                for (child in ds) {
                    if (!Files.isDirectory(child)) continue
                    try {
                        val s = State.load(rootPath, child.fileName.toString())
                            .refreshStatus()
                        states.add(s)
                    } catch (_: Exception) {
                    }
                }
            }
        } catch (e: IOException) {
            Logger.error("list failed: ${e.message}")
            return 1
        }

        // runc sorts containers by ID (alphabetical order).
        states.sortBy { it.id }

        if (quiet) {
            for (s in states) println(s.id)
            return 0
        }
        if (format == "json") {
            // runc list --format json emits a fixed field order:
            //   ociVersion, id, pid, status, bundle, rootfs, created
            // "rootfs" is derived from the bundle path and "annotations" is
            // omitted entirely.
            println(
                JsonCodec.encodeCompact(
                    JsonCodec.toJsonElement(
                        states.map { s ->
                            linkedMapOf<String, Any?>(
                                "ociVersion" to s.ociVersion,
                                "id" to s.id,
                                "pid" to s.pid,
                                "status" to s.status,
                                "bundle" to s.bundle,
                                "rootfs" to if (s.bundle != null) "${s.bundle}/rootfs" else "",
                                "created" to s.created
                            )
                        }
                    )
                )
            )
            return 0
        }
        // runc column order: ID PID STATUS BUNDLE CREATED OWNER
        System.out.printf("%-30s %-8s %-10s %-40s %s%n", "ID", "PID", "STATUS", "BUNDLE", "CREATED")
        for (s in states) {
            System.out.printf(
                "%-30s %-8s %-10s %-40s %s%n",
                s.id, s.pid ?: "-",
                s.status, s.bundle, s.created ?: "-"
            )
        }
        return 0
    }

    /** Default root for runc/takoyaki. */
    private fun isDefaultRoot(rootPath: String): Boolean =
        rootPath == "/run/takoyaki" || rootPath == "/run/runc"
}
