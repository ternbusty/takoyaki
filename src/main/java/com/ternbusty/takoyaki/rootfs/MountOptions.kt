package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.syscall.Constants

/**
 * Pure parser for OCI mount option tokens.
 *
 * Splits the option list into three buckets the kernel needs separately.
 *   flags        = MS_* bits that go in the first mount(2) call
 *   propagation  = MS_SHARED / MS_SLAVE / etc., set via a second mount(2) call
 *                  because the kernel rejects propagation mixed with regular flags
 *   data         = comma-joined "everything we didn't recognize" passed as the
 *                  fs-specific data string (e.g. "mode=755,size=64k")
 *
 * Extracted out of Rootfs so it's testable without a live mount namespace.
 */
object MountOptions {

    class Parsed internal constructor(
        val flags: Long,
        val propagation: Long,
        val data: String?,
        val isBind: Boolean,
        /** mount_setattr attr_set bitmask for AT_RECURSIVE application. */
        val recAttrSet: Long,
        /** mount_setattr attr_clr bitmask for AT_RECURSIVE application. */
        val recAttrClr: Long,
        /**
         * MS_* bits that the user explicitly asked to CLEAR. For example
         * "dev" clears MS_NODEV, "suid" clears MS_NOSUID. On a bind remount
         * these flags are NOT included (which clears them on the mount).
         */
        val clearedFlags: Long,
        /** OCI "tmpcopyup" option: copy rootfs contents into tmpfs after mount. */
        val tmpcopyup: Boolean,
        /** OCI "idmap" option: apply non-recursive id-mapped mount. */
        val isIdmap: Boolean,
        /** OCI "ridmap" option: apply recursive id-mapped mount. */
        val isRecursiveIdmap: Boolean,
    ) {
        /** True when mount_setattr(AT_RECURSIVE) should be called after mount. */
        fun hasRecAttr(): Boolean = recAttrSet != 0L || recAttrClr != 0L
    }

    /**
     * Map an OCI propagation name ("shared", "rslave", ...) to its MS_* flag
     * combination. Returns 0 for unknown names. Single owner of this mapping,
     * shared between [parse] and Rootfs' rootfsPropagation handling.
     */
    fun propagationFlag(name: String?): Long = when (name) {
        "shared" -> Constants.MS_SHARED
        "rshared" -> Constants.MS_SHARED or Constants.MS_REC
        "slave" -> Constants.MS_SLAVE
        "rslave" -> Constants.MS_SLAVE or Constants.MS_REC
        "private" -> Constants.MS_PRIVATE
        "rprivate" -> Constants.MS_PRIVATE or Constants.MS_REC
        "unbindable" -> Constants.MS_UNBINDABLE
        "runbindable" -> Constants.MS_UNBINDABLE or Constants.MS_REC
        else -> 0L
    }

    fun parse(options: List<String>?): Parsed {
        if (options == null) {
            return Parsed(0, 0, null, false, 0, 0, 0, tmpcopyup = false,
                isIdmap = false, isRecursiveIdmap = false)
        }
        var flags = 0L
        var propagation = 0L
        var recAttrSet = 0L
        var recAttrClr = 0L
        var clearedFlags = 0L
        val data = StringBuilder()
        var isBind = false
        var tmpcopyup = false
        var isIdmap = false
        var isRecursiveIdmap = false

        for (o in options) {
            when (o) {
                "bind" -> {
                    flags = flags or Constants.MS_BIND
                    isBind = true
                }
                "rbind" -> {
                    flags = flags or Constants.MS_BIND or Constants.MS_REC
                    isBind = true
                }
                "rw" -> { /* default (absence of MS_RDONLY) */ }
                "ro" -> flags = flags or Constants.MS_RDONLY
                "nosuid" -> flags = flags or Constants.MS_NOSUID
                "noexec" -> flags = flags or Constants.MS_NOEXEC
                "nodev" -> flags = flags or Constants.MS_NODEV
                "noatime" -> flags = flags or Constants.MS_NOATIME
                "relatime" -> flags = flags or Constants.MS_RELATIME
                "strictatime" -> flags = flags or Constants.MS_STRICTATIME
                "nosymfollow" -> flags = flags or Constants.MS_NOSYMFOLLOW
                "nodiratime" -> flags = flags or Constants.MS_NODIRATIME
                "rec" -> flags = flags or Constants.MS_REC

                // Clearing options: explicitly ask to REMOVE a flag from a
                // bind mount's inherited settings (runc specconv "ClearedFlags").
                "suid" -> clearedFlags = clearedFlags or Constants.MS_NOSUID
                "exec" -> clearedFlags = clearedFlags or Constants.MS_NOEXEC
                "dev" -> clearedFlags = clearedFlags or Constants.MS_NODEV
                "atime" -> clearedFlags = clearedFlags or Constants.MS_NOATIME
                "diratime" -> clearedFlags = clearedFlags or Constants.MS_NODIRATIME
                "symfollow" -> clearedFlags = clearedFlags or Constants.MS_NOSYMFOLLOW
                "norelatime" -> { /* clearing relatime is not a real flag */ }

                // Recursive mount attribute options (mount_setattr + AT_RECURSIVE).
                // "set" entries add to attr_set; "clear" entries add to attr_clr.
                "rro" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_RDONLY
                "rrw" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_RDONLY
                "rnosuid" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NOSUID
                "rsuid" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NOSUID
                "rnodev" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NODEV
                "rdev" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NODEV
                "rnoexec" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NOEXEC
                "rexec" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NOEXEC
                "rnosymfollow" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NOSYMFOLLOW
                "rsymfollow" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NOSYMFOLLOW
                // Atime-family: the kernel requires MOUNT_ATTR__ATIME in attr_clr
                // whenever any atime-related attribute is being changed. That is
                // applied in a fixup pass after the loop.
                "rnoatime" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NOATIME
                "ratime" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NOATIME
                "rstrictatime" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_STRICTATIME
                "rnostrictatime" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_STRICTATIME
                "rnodiratime" -> recAttrSet = recAttrSet or Constants.MOUNT_ATTR_NODIRATIME
                "rdiratime" -> recAttrClr = recAttrClr or Constants.MOUNT_ATTR_NODIRATIME
                "rrelatime" -> { /* MOUNT_ATTR_RELATIME is 0; clearing __ATIME gives relatime */ }
                "rnorelatime" -> { /* same effect as rrelatime (clearing __ATIME) */ }

                // OCI extension: copy pre-existing rootfs directory contents
                // into the tmpfs after mounting. Recognised as a flag, not
                // passed through to mount data.
                "tmpcopyup" -> tmpcopyup = true

                // OCI id-mapped mount options. "idmap" applies the mapping
                // non-recursively; "ridmap" applies recursively via
                // AT_RECURSIVE in mount_setattr.
                "idmap" -> isIdmap = true
                "ridmap" -> isRecursiveIdmap = true

                else -> {
                    val prop = propagationFlag(o)
                    if (prop != 0L) {
                        propagation = prop
                    } else {
                        if (data.isNotEmpty()) data.append(",")
                        data.append(o)
                    }
                }
            }
        }
        // mount_setattr(2) man page: "cannot simply specify the access-time
        // setting in attr_set, but must also include MOUNT_ATTR__ATIME in the
        // attr_clr field." Any atime-related flag (including the no-op
        // MOUNT_ATTR_RELATIME = 0) triggers this requirement.
        val atimeOptions = setOf(
            "rrelatime", "rnorelatime", "rnoatime", "ratime",
            "rstrictatime", "rnostrictatime", "rnodiratime", "rdiratime"
        )
        if ((recAttrSet and Constants.MOUNT_ATTR__ATIME) != 0L
            || (recAttrClr and Constants.MOUNT_ATTR__ATIME) != 0L
            || options.any { it in atimeOptions }
        ) {
            recAttrClr = recAttrClr or Constants.MOUNT_ATTR__ATIME
        }
        return Parsed(
            flags, propagation,
            if (data.isNotEmpty()) data.toString() else null,
            isBind, recAttrSet, recAttrClr, clearedFlags, tmpcopyup,
            isIdmap, isRecursiveIdmap
        )
    }
}
