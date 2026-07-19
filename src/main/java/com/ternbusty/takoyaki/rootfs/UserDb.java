package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Ensure the container has /etc/passwd and /etc/group entries for the target uid/gid
 * so commands like `id`, `whoami`, `groups` don't fail with "unknown user".
 *
 * Skipped silently if /etc already missing (e.g. scratch image) or the entries
 * are already present.
 */
public final class UserDb {
    private UserDb() {}

    public static void ensure(Spec.User user) {
        if (user == null) return;
        addPasswd(user.uid, user.gid);
        addGroups(user);
    }

    private static void addPasswd(int uid, int gid) {
        Path p = Path.of("/etc/passwd");
        if (!Files.exists(p)) return;
        try {
            String content = Files.readString(p);
            if (lineForUid(content, uid) != null) return;
            String entry = "container:x:" + uid + ":" + gid
                    + ":container user:/:/sbin/nologin\n";
            Files.writeString(p, entry, StandardOpenOption.APPEND);
            Logger.debug("/etc/passwd entry added for uid=" + uid);
        } catch (IOException e) {
            Logger.debug("/etc/passwd update skipped: " + e.getMessage());
        }
    }

    private static void addGroups(Spec.User user) {
        Path p = Path.of("/etc/group");
        if (!Files.exists(p)) return;
        try {
            // Read once, compute every missing gid against that single content,
            // and append all missing entries in one write.
            String content = Files.readString(p);
            Set<Integer> pending = new LinkedHashSet<>();
            StringBuilder entries = new StringBuilder();
            appendIfMissing(content, pending, entries, user.gid, "user");
            if (user.additionalGids != null) {
                for (int gid : user.additionalGids) {
                    if (gid != user.gid) {
                        appendIfMissing(content, pending, entries, gid, "extra" + gid);
                    }
                }
            }
            if (entries.length() == 0) return;
            Files.writeString(p, entries.toString(), StandardOpenOption.APPEND);
        } catch (IOException e) {
            Logger.debug("/etc/group update skipped: " + e.getMessage());
        }
    }

    private static void appendIfMissing(String content, Set<Integer> pending,
                                        StringBuilder entries, int gid, String fallbackName) {
        if (lineForGid(content, gid) != null) return;
        if (!pending.add(gid)) return;
        entries.append(fallbackName).append(":x:").append(gid).append(":\n");
        Logger.debug("/etc/group entry added for gid=" + gid);
    }

    private static String lineForUid(String content, int uid) {
        String marker = ":" + uid + ":";
        for (String line : content.split("\n")) {
            if (line.contains(marker)) return line;
        }
        return null;
    }

    private static String lineForGid(String content, int gid) {
        String suffix = ":x:" + gid + ":";
        for (String line : content.split("\n")) {
            if (line.contains(suffix)) return line;
        }
        return null;
    }
}
