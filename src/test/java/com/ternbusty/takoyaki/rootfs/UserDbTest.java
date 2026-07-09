package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.spec.Spec;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class UserDbTest {

    private static Spec.User user(int uid, int gid) {
        Spec.User u = new Spec.User();
        u.uid = uid;
        u.gid = gid;
        return u;
    }

    @Test
    void nullUserIsNoOp() {
        // Spec without process.user defaults to nothing. We must not touch the
        // image rootfs in that case.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            UserDb.ensure(null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void missingEtcSkipsSilently() {
        // Scratch images have no /etc at all. We must not blow up.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(false);

            UserDb.ensure(user(1000, 1000));

            // Read/write must NEVER happen when the files don't exist.
            fm.verify(() -> Files.readString(any(Path.class)), never());
            fm.verify(() -> Files.writeString(any(Path.class), anyString(),
                    any(OpenOption.class)), never());
        }
    }

    @Test
    void existingUidEntryIsSkippedNotDuplicated() {
        // If /etc/passwd already lists the uid (e.g. busybox's "root:x:0:0"),
        // we MUST NOT append a second line. Idempotency matters because hooks
        // can re-trigger ensure().
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            fm.when(() -> Files.readString(eq(Path.of("/etc/passwd"))))
                    .thenReturn("root:x:0:0:root:/root:/bin/sh\n");
            fm.when(() -> Files.readString(eq(Path.of("/etc/group"))))
                    .thenReturn("root:x:0:\n");

            UserDb.ensure(user(0, 0));

            fm.verify(() -> Files.writeString(any(Path.class), anyString(),
                    any(OpenOption.class)), never());
        }
    }

    @Test
    void missingUidEntryIsAppendedToPasswd() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            fm.when(() -> Files.readString(eq(Path.of("/etc/passwd"))))
                    .thenReturn("root:x:0:0:root:/root:/bin/sh\n");
            fm.when(() -> Files.readString(eq(Path.of("/etc/group"))))
                    .thenReturn("root:x:0:\n");
            fm.when(() -> Files.writeString(any(Path.class), anyString(),
                    any(OpenOption.class))).thenReturn(Path.of("/dev/null"));

            UserDb.ensure(user(1000, 1000));

            // The entry shape is hard-coded to "container:x:<uid>:<gid>:container user:/:/sbin/nologin\n".
            // It's intentional that the shell is /sbin/nologin — runtime-tools doesn't run anything
            // under this account, it just needs the lookup to succeed.
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/etc/passwd")),
                    eq("container:x:1000:1000:container user:/:/sbin/nologin\n"),
                    any(OpenOption.class)));
        }
    }

    @Test
    void missingGidEntryIsAppendedToGroup() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            // /etc/passwd already has the uid -> no passwd write
            fm.when(() -> Files.readString(eq(Path.of("/etc/passwd"))))
                    .thenReturn("container:x:1000:1000:c:/:/sbin/nologin\n");
            // /etc/group lacks gid=1000 -> append
            fm.when(() -> Files.readString(eq(Path.of("/etc/group"))))
                    .thenReturn("root:x:0:\n");
            fm.when(() -> Files.writeString(any(Path.class), anyString(),
                    any(OpenOption.class))).thenReturn(Path.of("/dev/null"));

            UserDb.ensure(user(1000, 1000));

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/etc/group")),
                    eq("user:x:1000:\n"),
                    any(OpenOption.class)));
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/etc/passwd")),
                    anyString(), any(OpenOption.class)), never());
        }
    }

    @Test
    void additionalGidsAreAppendedExceptDuplicateOfPrimaryGid() {
        // additionalGids is supplementary. If one of them is == primary gid,
        // we must NOT emit "extra<gid>" for it (else two lines for the same gid).
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            fm.when(() -> Files.readString(eq(Path.of("/etc/passwd"))))
                    .thenReturn("container:x:1000:1000:c:/:/sbin/nologin\n");
            fm.when(() -> Files.readString(eq(Path.of("/etc/group"))))
                    .thenReturn("");
            fm.when(() -> Files.writeString(any(Path.class), anyString(),
                    any(OpenOption.class))).thenReturn(Path.of("/dev/null"));

            Spec.User u = user(1000, 1000);
            u.additionalGids = List.of(1000, 100, 200);
            UserDb.ensure(u);

            // All missing entries land in ONE append. Primary gid=1000 appears
            // once via the "user" entry and must NOT come back as "extra1000";
            // the non-duplicate supplementary gids do get appended.
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/etc/group")),
                    eq("user:x:1000:\nextra100:x:100:\nextra200:x:200:\n"),
                    any(OpenOption.class)));
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/etc/group")),
                    anyString(), any(OpenOption.class)), times(1));
        }
    }

    @Test
    void readFailureIsLoggedNotPropagated() {
        // If /etc/passwd is symlinked weirdly or sealed, Files.readString throws.
        // The runtime must NOT die — UserDb is a best-effort convenience.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            fm.when(() -> Files.readString(any(Path.class)))
                    .thenThrow(new IOException("EACCES"));

            assertDoesNotThrow(() -> UserDb.ensure(user(1000, 1000)));
        }
    }
}
