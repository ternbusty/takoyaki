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

        Parsed(long flags, long propagation, String data, boolean isBind) {
            this.flags = flags;
            this.propagation = propagation;
            this.data = data;
            this.isBind = isBind;
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
        StringBuilder data = new StringBuilder();
        boolean isBind = false;
        if (options == null) {
            return new Parsed(0, 0, null, false);
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
                case "ro":          flags |= Constants.MS_RDONLY;       break;
                case "nosuid":      flags |= Constants.MS_NOSUID;       break;
                case "noexec":      flags |= Constants.MS_NOEXEC;       break;
                case "nodev":       flags |= Constants.MS_NODEV;        break;
                case "noatime":     flags |= Constants.MS_NOATIME;      break;
                case "relatime":    flags |= Constants.MS_RELATIME;     break;
                case "strictatime": flags |= Constants.MS_STRICTATIME;  break;
                case "nosymfollow": flags |= Constants.MS_NOSYMFOLLOW;  break;
                case "rec":         flags |= Constants.MS_REC;          break;
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
        return new Parsed(flags, propagation, data.length() > 0 ? data.toString() : null, isBind);
    }
}
