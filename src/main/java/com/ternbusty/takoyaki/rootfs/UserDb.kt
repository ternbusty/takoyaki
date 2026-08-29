package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * Ensure the container has /etc/passwd and /etc/group entries for the target uid/gid
 * so commands like `id`, `whoami`, `groups` don't fail with "unknown user".
 *
 * Skipped silently if /etc already missing (e.g. scratch image) or the entries
 * are already present.
 */
object UserDb {

    fun ensure(user: User?) {
        if (user == null) return
        addPasswd(user.uid, user.gid)
        addGroups(user)
    }

    private fun addPasswd(uid: Int, gid: Int) {
        val p = Path.of("/etc/passwd")
        if (!Files.exists(p)) return
        try {
            val content = Files.readString(p)
            if (lineForUid(content, uid) != null) return
            // Use /root for uid 0, /home/<name> otherwise. runc uses /
            // but many tests rely on HOME being set from /etc/passwd.
            val home = if (uid == 0) "/root" else "/"
            val entry = "container:x:$uid:$gid:container user:$home:/sbin/nologin\n"
            Files.writeString(p, entry, StandardOpenOption.APPEND)
            Logger.debug("/etc/passwd entry added for uid=$uid")
        } catch (e: IOException) {
            Logger.debug("/etc/passwd update skipped: ${e.message}")
        }
    }

    private fun addGroups(user: User) {
        val p = Path.of("/etc/group")
        if (!Files.exists(p)) return
        try {
            // Read once, compute every missing gid against that single content,
            // and append all missing entries in one write.
            val content = Files.readString(p)
            val pending = linkedSetOf<Int>()
            val entries = StringBuilder()
            appendIfMissing(content, pending, entries, user.gid, "user")
            if (user.additionalGids != null) {
                for (gid in user.additionalGids) {
                    if (gid != user.gid) {
                        appendIfMissing(content, pending, entries, gid, "extra$gid")
                    }
                }
            }
            if (entries.isEmpty()) return
            Files.writeString(p, entries.toString(), StandardOpenOption.APPEND)
        } catch (e: IOException) {
            Logger.debug("/etc/group update skipped: ${e.message}")
        }
    }

    private fun appendIfMissing(
        content: String,
        pending: MutableSet<Int>,
        entries: StringBuilder,
        gid: Int,
        fallbackName: String,
    ) {
        if (lineForGid(content, gid) != null) return
        if (!pending.add(gid)) return
        entries.append(fallbackName).append(":x:").append(gid).append(":\n")
        Logger.debug("/etc/group entry added for gid=$gid")
    }

    private fun lineForUid(content: String, uid: Int): String? {
        val marker = ":$uid:"
        for (line in content.split("\n")) {
            if (marker in line) return line
        }
        return null
    }

    private fun lineForGid(content: String, gid: Int): String? {
        val suffix = ":x:$gid:"
        for (line in content.split("\n")) {
            if (suffix in line) return line
        }
        return null
    }

    /**
     * Lookup the home directory for the given uid from /etc/passwd inside the
     * container. Returns null if the file does not exist or the uid is not
     * found.
     *
     * passwd format is `name:password:uid:gid:gecos:home:shell`.
     */
    fun lookupHome(uid: Int): String? {
        val p = Path.of("/etc/passwd")
        if (!Files.exists(p)) return null
        try {
            val content = Files.readString(p)
            for (line in content.split("\n")) {
                if (line.isEmpty() || line.startsWith("#")) continue
                // Find fields: split lazily. The uid lives at field [2].
                val parts = line.split(":")
                if (parts.size >= 6) {
                    try {
                        if (parts[2].toInt() == uid) {
                            return parts[5]
                        }
                    } catch (_: NumberFormatException) {
                    }
                }
            }
        } catch (e: IOException) {
            Logger.debug("/etc/passwd lookup failed: ${e.message}")
        }
        return null
    }
}
