package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.PosixIO

import java.io.IOException
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path

/**
 * Create a temporary user namespace populated with the given uid/gid mappings,
 * return its /proc/<helper>/ns/user fd, and apply MOUNT_ATTR_IDMAP to a clone of the
 * source path before move-mounting it to the destination.
 *
 * IMPORTANT: this helper has TWO entry points.
 *
 * [setupHostSide] is called from the takoyaki main process BEFORE forking
 * the bootstrap. It runs on the host (host pid namespace, host /proc) so it can
 * address its forked helper via host pids. The returned fd survives the fork +
 * execve and is then handed to the init via env var.
 *
 * [apply] is the in-init path used when the setup wasn't done on the host
 * (it only works for non-userns containers; for userns containers /proc and pids
 * get out of sync and mount_setattr returns EPERM). Prefer the host-side path.
 */
class IdmapHelper private constructor() {

    companion object {

        /** Apply an id-mapped bind mount from [m]`.source` to [destination]. */
        fun apply(m: Mount, destination: String): Boolean =
            apply(m, destination, recursive = false, cloneRecursive = false)

        /**
         * Apply an id-mapped bind mount.
         *
         * @param recursive      pass AT_RECURSIVE to mount_setattr (ridmap semantics)
         * @param cloneRecursive pass AT_RECURSIVE to open_tree so submounts of the
         *                       source are included (needed for rbind sources whose
         *                       subtrees contain earlier mounts from the same spec)
         */
        fun apply(
            m: Mount, destination: String,
            recursive: Boolean, cloneRecursive: Boolean
        ): Boolean {
            val uidMaps = m.uidMappings
            if (uidMaps == null || uidMaps.isEmpty()) return false
            val usernsFd = openMappedUserNs(uidMaps, m.gidMappings)
            if (usernsFd < 0) return false
            return try {
                val src = m.source ?: return false
                IdmapMount.apply(src, usernsFd, destination, recursive, cloneRecursive)
            } finally {
                PosixIO.close(usernsFd)
            }
        }

        fun applyWithFd(m: Mount, usernsFd: Int, destination: String): Boolean =
            applyWithFd(m, usernsFd, destination, recursive = false, cloneRecursive = false)

        fun applyWithFd(
            m: Mount, usernsFd: Int, destination: String,
            recursive: Boolean, cloneRecursive: Boolean
        ): Boolean {
            val src = m.source ?: return false
            return IdmapMount.apply(src, usernsFd, destination, recursive, cloneRecursive)
        }

        /**
         * Host-side setup: spawn a helper process that unshares CLONE_NEWUSER, then
         * write uid_map/gid_map from this (parent) process via host /proc, open
         * /proc/<helper>/ns/user and return the fd. The helper exits once released.
         */
        fun setupHostSide(
            uidMaps: List<LinuxIdMapping>,
            gidMaps: List<LinuxIdMapping>
        ): Int = openMappedUserNs(uidMaps, gidMaps)

        /**
         * Spawn a helper process via ProcessBuilder that unshares CLONE_NEWUSER,
         * write the mappings to /proc/<helper>/uid_map and /proc/<helper>/gid_map
         * from this process, then open /proc/<helper>/ns/user.
         *
         * The helper is /proc/self/exe with _TAKOYAKI_IDMAP_HELPER set in its
         * environment. bootstrap.c's constructor intercepts this env var and
         * does unshare + stdout/stdin sync entirely in C, calling _exit(0)
         * before SubstrateVM ever starts. This avoids the safepoint deadlock
         * that occurs when forking from a multi-threaded SubstrateVM process.
         */
        private fun openMappedUserNs(
            uidMaps: List<LinuxIdMapping>,
            gidMaps: List<LinuxIdMapping>?
        ): Int {
            val helper = try {
                ProcessBuilder("/proc/self/exe").apply {
                    environment()["_TAKOYAKI_IDMAP_HELPER"] = "1"
                    redirectError(ProcessBuilder.Redirect.INHERIT)
                }.start()
            } catch (e: IOException) {
                Logger.warn("idmap helper process start failed: ${e.message}")
                return -1
            }

            val pid = helper.pid()
            try {
                helper.inputStream.use { input ->
                    helper.outputStream.use { output ->
                        // Wait for the helper to signal that unshare(CLONE_NEWUSER) completed.
                        val syncByte = input.read()
                        if (syncByte != 1) {
                            Logger.warn("idmap helper unshare(CLONE_NEWUSER) failed (sync=$syncByte)")
                            helper.destroyForcibly()
                            return -1
                        }

                        if (Logger.isDebugEnabled) {
                            try {
                                val helperLink = Files.readSymbolicLink(Path.of("/proc/$pid/ns/user")).toString()
                                val myLink = Files.readSymbolicLink(Path.of("/proc/self/ns/user")).toString()
                                Logger.debug(
                                    "idmap parent pid=${ProcessHandle.current().pid()}" +
                                    " helperPid=$pid helper=$helperLink ours=$myLink"
                                )
                                if (helperLink == myLink) {
                                    Logger.warn("idmap helper userns same as ours ($myLink); unshare lied")
                                }
                            } catch (_: IOException) {
                            }
                        }

                        // Write maps from this process's privileged context.
                        writeMappings(pid, uidMaps, "uid_map")
                        writeMappings(pid, gidMaps, "gid_map")

                        if (Logger.isDebugEnabled) {
                            try {
                                val uidMapContent = Files.readString(Path.of("/proc/$pid/uid_map"))
                                val gidMapContent = Files.readString(Path.of("/proc/$pid/gid_map"))
                                Logger.debug(
                                    "idmap helper uid_map=${uidMapContent.replace("\n", "|")}" +
                                    " gid_map=${gidMapContent.replace("\n", "|")}"
                                )
                            } catch (e: IOException) {
                                Logger.warn("could not read back idmap helper maps: ${e.message}")
                            }
                        }

                        // Open the helper's userns fd while it is still alive.
                        val fd = Arena.ofConfined().use { arena ->
                            PosixIO.open(arena, "/proc/$pid/ns/user", Constants.O_RDONLY, 0)
                        }

                        // Release the helper so it can _exit(0).
                        output.write(1)
                        output.flush()

                        helper.waitFor()

                        if (fd < 0) {
                            Logger.warn("open helper userns fd failed")
                        }
                        return fd
                    }
                }
            } catch (e: IOException) {
                Logger.warn("idmap helper communication failed: ${e.message}")
                helper.destroyForcibly()
                return -1
            } catch (e: InterruptedException) {
                Logger.warn("idmap helper communication failed: ${e.message}")
                helper.destroyForcibly()
                return -1
            }
        }

        /**
         * Write a userns map intended to drive mount_setattr(MOUNT_ATTR_IDMAP).
         *
         * The uid_map format is `"inside outside count"`. For an idmap userns
         * the kernel's make_vfsuid() calls from_kuid(idmap_userns, disk_kuid) which
         * uses map_id_up: it looks up disk_kuid in the OUTSIDE column and returns
         * the INSIDE value. So to make "disk uid 0 appear as containerID 100000"
         * with OCI mapping {containerID=0, hostID=100000} we write
         * `"containerID hostID size"` = `"0 100000 65536"` so that
         * INSIDE=containerID=0 and OUTSIDE=hostID=100000. Then map_id_up(disk_uid=0)
         * finds 0 in [outside=100000..165535]? No, that does not match for disk_uid=0.
         *
         * Actually: for an idmap mount the OCI spec semantics are that hostID is the
         * on-disk UID and containerID is what shows through the mount. Verified
         * empirically: the kernel's from_kuid maps disk UIDs via the OUTSIDE column
         * of the userns uid_map. Writing "containerID hostID size" (= "0 100000
         * 65536") makes disk uid 0 appear as uid 100000 through the mount, matching
         * runc's behaviour. This is the SAME direction as a process-attached userns.
         */
        private fun writeMappings(pid: Long, maps: List<LinuxIdMapping>?, file: String) {
            if (maps.isNullOrEmpty()) return
            val content = buildString {
                for (m in maps) {
                    append("${m.containerID} ${m.hostID} ${m.size}\n")
                }
            }
            try {
                Files.writeString(Path.of("/proc/$pid/$file"), content)
            } catch (e: IOException) {
                Logger.warn("write /proc/$pid/$file failed: ${e.message}")
            }
        }
    }
}
