package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.syscall.Constants;

import java.util.List;

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
public final class MountOptions {
    private MountOptions() {}

    public static final class Parsed {
        public final long flags;
        public final long propagation;
        public final String data;
        public final boolean isBind;
        /** mount_setattr attr_set bitmask for AT_RECURSIVE application. */
        public final long recAttrSet;
        /** mount_setattr attr_clr bitmask for AT_RECURSIVE application. */
        public final long recAttrClr;
        /**
         * MS_* bits that the user explicitly asked to CLEAR. For example
         * "dev" clears MS_NODEV, "suid" clears MS_NOSUID. On a bind remount
         * these flags are NOT included (which clears them on the mount).
         */
        public final long clearedFlags;
        /** OCI "tmpcopyup" option: copy rootfs contents into tmpfs after mount. */
        public final boolean tmpcopyup;

        Parsed(long flags, long propagation, String data, boolean isBind,
               long recAttrSet, long recAttrClr, long clearedFlags,
               boolean tmpcopyup) {
            this.flags = flags;
            this.propagation = propagation;
            this.data = data;
            this.isBind = isBind;
            this.recAttrSet = recAttrSet;
            this.recAttrClr = recAttrClr;
            this.clearedFlags = clearedFlags;
            this.tmpcopyup = tmpcopyup;
        }

        /** True when mount_setattr(AT_RECURSIVE) should be called after mount. */
        public boolean hasRecAttr() {
            return recAttrSet != 0 || recAttrClr != 0;
        }
    }

    /**
     * Map an OCI propagation name ("shared", "rslave", ...) to its MS_* flag
     * combination. Returns 0 for unknown names. Single owner of this mapping,
     * shared between {@link #parse} and Rootfs' rootfsPropagation handling.
     */
    public static long propagationFlag(String name) {
        if (name == null) return 0L;
        return switch (name) {
            case "shared"      -> Constants.MS_SHARED;
            case "rshared"     -> Constants.MS_SHARED | Constants.MS_REC;
            case "slave"       -> Constants.MS_SLAVE;
            case "rslave"      -> Constants.MS_SLAVE | Constants.MS_REC;
            case "private"     -> Constants.MS_PRIVATE;
            case "rprivate"    -> Constants.MS_PRIVATE | Constants.MS_REC;
            case "unbindable"  -> Constants.MS_UNBINDABLE;
            case "runbindable" -> Constants.MS_UNBINDABLE | Constants.MS_REC;
            default            -> 0L;
        };
    }

    public static Parsed parse(List<String> options) {
        long flags = 0;
        long propagation = 0;
        long recAttrSet = 0;
        long recAttrClr = 0;
        long clearedFlags = 0;
        StringBuilder data = new StringBuilder();
        boolean isBind = false;
        boolean tmpcopyup = false;
        if (options == null) {
            return new Parsed(0, 0, null, false, 0, 0, 0, false);
        }
        for (String o : options) {
            switch (o) {
                case "bind":
                    flags |= Constants.MS_BIND;
                    isBind = true;
                    break;
                case "rbind":
                    flags |= Constants.MS_BIND | Constants.MS_REC;
                    isBind = true;
                    break;
                case "rw":          /* default (absence of MS_RDONLY) */ break;
                case "ro":          flags |= Constants.MS_RDONLY;       break;
                case "nosuid":      flags |= Constants.MS_NOSUID;       break;
                case "noexec":      flags |= Constants.MS_NOEXEC;       break;
                case "nodev":       flags |= Constants.MS_NODEV;        break;
                case "noatime":     flags |= Constants.MS_NOATIME;      break;
                case "relatime":    flags |= Constants.MS_RELATIME;     break;
                case "strictatime": flags |= Constants.MS_STRICTATIME;  break;
                case "nosymfollow": flags |= Constants.MS_NOSYMFOLLOW;  break;
                case "nodiratime":  flags |= Constants.MS_NODIRATIME;   break;
                case "rec":         flags |= Constants.MS_REC;          break;

                // Clearing options: explicitly ask to REMOVE a flag from a
                // bind mount's inherited settings (runc specconv "ClearedFlags").
                case "suid":        clearedFlags |= Constants.MS_NOSUID;     break;
                case "exec":        clearedFlags |= Constants.MS_NOEXEC;     break;
                case "dev":         clearedFlags |= Constants.MS_NODEV;      break;
                case "atime":       clearedFlags |= Constants.MS_NOATIME;    break;
                case "diratime":    clearedFlags |= Constants.MS_NODIRATIME; break;
                case "symfollow":   clearedFlags |= Constants.MS_NOSYMFOLLOW; break;
                case "norelatime":  /* clearing relatime is not a real flag */ break;

                // Recursive mount attribute options (mount_setattr + AT_RECURSIVE).
                // "set" entries add to attr_set; "clear" entries add to attr_clr.
                case "rro":            recAttrSet |= Constants.MOUNT_ATTR_RDONLY;       break;
                case "rrw":            recAttrClr |= Constants.MOUNT_ATTR_RDONLY;       break;
                case "rnosuid":        recAttrSet |= Constants.MOUNT_ATTR_NOSUID;       break;
                case "rsuid":          recAttrClr |= Constants.MOUNT_ATTR_NOSUID;       break;
                case "rnodev":         recAttrSet |= Constants.MOUNT_ATTR_NODEV;        break;
                case "rdev":           recAttrClr |= Constants.MOUNT_ATTR_NODEV;        break;
                case "rnoexec":        recAttrSet |= Constants.MOUNT_ATTR_NOEXEC;       break;
                case "rexec":          recAttrClr |= Constants.MOUNT_ATTR_NOEXEC;       break;
                case "rnosymfollow":   recAttrSet |= Constants.MOUNT_ATTR_NOSYMFOLLOW;  break;
                case "rsymfollow":     recAttrClr |= Constants.MOUNT_ATTR_NOSYMFOLLOW;  break;
                // Atime-family: the kernel requires MOUNT_ATTR__ATIME in attr_clr
                // whenever any atime-related attribute is being changed. That is
                // applied in a fixup pass after the loop.
                case "rnoatime":       recAttrSet |= Constants.MOUNT_ATTR_NOATIME;      break;
                case "ratime":         recAttrClr |= Constants.MOUNT_ATTR_NOATIME;      break;
                case "rstrictatime":   recAttrSet |= Constants.MOUNT_ATTR_STRICTATIME;  break;
                case "rnostrictatime": recAttrClr |= Constants.MOUNT_ATTR_STRICTATIME;  break;
                case "rnodiratime":    recAttrSet |= Constants.MOUNT_ATTR_NODIRATIME;   break;
                case "rdiratime":      recAttrClr |= Constants.MOUNT_ATTR_NODIRATIME;   break;
                case "rrelatime":      /* MOUNT_ATTR_RELATIME is 0; clearing __ATIME gives relatime */ break;
                case "rnorelatime":    /* same effect as rrelatime (clearing __ATIME) */                break;

                // OCI extension: copy pre-existing rootfs directory contents
                // into the tmpfs after mounting. Recognised as a flag, not
                // passed through to mount data.
                case "tmpcopyup":      tmpcopyup = true; break;

                default:
                    long prop = propagationFlag(o);
                    if (prop != 0) {
                        propagation = prop;
                        break;
                    }
                    if (data.length() > 0) data.append(",");
                    data.append(o);
            }
        }
        // mount_setattr(2) man page: "cannot simply specify the access-time
        // setting in attr_set, but must also include MOUNT_ATTR__ATIME in the
        // attr_clr field." Any atime-related flag (including the no-op
        // MOUNT_ATTR_RELATIME = 0) triggers this requirement.
        if ((recAttrSet & Constants.MOUNT_ATTR__ATIME) != 0
                || (recAttrClr & Constants.MOUNT_ATTR__ATIME) != 0
                || options.stream().anyMatch(o ->
                    o.equals("rrelatime") || o.equals("rnorelatime")
                    || o.equals("rnoatime") || o.equals("ratime")
                    || o.equals("rstrictatime") || o.equals("rnostrictatime")
                    || o.equals("rnodiratime") || o.equals("rdiratime"))) {
            recAttrClr |= Constants.MOUNT_ATTR__ATIME;
        }
        return new Parsed(flags, propagation,
                data.length() > 0 ? data.toString() : null,
                isBind, recAttrSet, recAttrClr, clearedFlags, tmpcopyup);
    }
}
