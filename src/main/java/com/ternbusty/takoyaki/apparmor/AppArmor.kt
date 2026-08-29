package com.ternbusty.takoyaki.apparmor

import com.ternbusty.takoyaki.logger.Logger
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Apply an AppArmor profile to the calling thread by writing to
 * `/proc/self/attr/apparmor/exec` (preferred, kernel >=5.8) or
 * `/proc/self/attr/exec` (legacy). The profile takes effect on the next
 * exec(2) on this thread.
 *
 * Stage this before PR_SET_NO_NEW_PRIVS and before dropping privileges. It is
 * the first privilege step in init, ahead of NNP and the capability/uid drop.
 * Once no_new_privs is set the kernel refuses an on-exec transition to a
 * different profile, so staging it afterwards would fail.
 */
object AppArmor {

    fun apply(profile: String?) {
        if (profile.isNullOrEmpty() || profile == "unconfined") return
        // Don't check /sys/kernel/security/apparmor here: this runs after pivot_root,
        // and the container rootfs typically does not mount securityfs. Rely on the
        // existence check inside writeAttr (/proc/self/attr/... is always available
        // because /proc is mounted in the container).
        val command = "exec $profile".toByteArray()

        // Prefer the newer per-LSM path; fall back to the legacy attr/exec.
        if (writeAttr("/proc/self/attr/apparmor/exec", command)) {
            Logger.debug("apparmor profile staged via attr/apparmor/exec: $profile")
            return
        }
        if (writeAttr("/proc/self/attr/exec", command)) {
            Logger.debug("apparmor profile staged via attr/exec: $profile")
            return
        }
        Logger.warn("apparmor profile write failed for both paths: $profile")
    }

    /**
     * Write the command in one write(2) syscall via FileOutputStream so the kernel
     * sees the exact buffer (no trailing newline, no readback).
     */
    private fun writeAttr(path: String, command: ByteArray): Boolean {
        if (!Files.exists(Path.of(path))) return false
        return try {
            FileOutputStream(path).use { out -> out.write(command) }
            true
        } catch (e: IOException) {
            Logger.debug("apparmor write $path failed: ${e.message}")
            false
        }
    }
}
