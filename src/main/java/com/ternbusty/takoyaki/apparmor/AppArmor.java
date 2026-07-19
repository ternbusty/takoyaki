package com.ternbusty.takoyaki.apparmor;

import com.ternbusty.takoyaki.logger.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Apply an AppArmor profile to the calling thread by writing to
 * {@code /proc/self/attr/apparmor/exec} (preferred, kernel >=5.8) or
 * {@code /proc/self/attr/exec} (legacy). The profile takes effect on the next
 * exec(2) on this thread.
 *
 * Stage this before PR_SET_NO_NEW_PRIVS and before dropping privileges. It is
 * the first privilege step in init, ahead of NNP and the capability/uid drop.
 * Once no_new_privs is set the kernel refuses an on-exec transition to a
 * different profile, so staging it afterwards would fail.
 */
public final class AppArmor {
    private AppArmor() {}

    public static void apply(String profile) {
        if (profile == null || profile.isEmpty() || "unconfined".equals(profile)) return;
        // Don't check /sys/kernel/security/apparmor here: this runs after pivot_root,
        // and the container rootfs typically does not mount securityfs. Rely on the
        // existence check inside writeAttr (/proc/self/attr/... is always available
        // because /proc is mounted in the container).
        byte[] command = ("exec " + profile).getBytes();

        // Prefer the newer per-LSM path; fall back to the legacy attr/exec.
        if (writeAttr("/proc/self/attr/apparmor/exec", command)) {
            Logger.debug("apparmor profile staged via attr/apparmor/exec: " + profile);
            return;
        }
        if (writeAttr("/proc/self/attr/exec", command)) {
            Logger.debug("apparmor profile staged via attr/exec: " + profile);
            return;
        }
        Logger.warn("apparmor profile write failed for both paths: " + profile);
    }

    /**
     * Write the command in one write(2) syscall via FileOutputStream so the kernel
     * sees the exact buffer (no trailing newline, no readback).
     */
    private static boolean writeAttr(String path, byte[] command) {
        if (!Files.exists(Path.of(path))) return false;
        try (FileOutputStream out = new FileOutputStream(path)) {
            out.write(command);
            return true;
        } catch (IOException e) {
            Logger.debug("apparmor write " + path + " failed: " + e.getMessage());
            return false;
        }
    }
}
