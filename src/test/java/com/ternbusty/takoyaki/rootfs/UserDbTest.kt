package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.spec.*
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.*
import java.io.IOException
import java.nio.file.Files
import java.nio.file.OpenOption
import java.nio.file.Path

class UserDbTest {

    companion object {
        private fun user(uid: Int, gid: Int): User =
            User(uid = uid, gid = gid)
    }

    @Test
    fun nullUserIsNoOp() {
        // Spec without process.user defaults to nothing. We must not touch the
        // image rootfs in that case.
        mockStatic(Files::class.java).use { fm ->
            UserDb.ensure(null)
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun missingEtcSkipsSilently() {
        // Scratch images have no /etc at all. We must not blow up.
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(false)

            UserDb.ensure(user(1000, 1000))

            // Read/write must NEVER happen when the files don't exist.
            fm.verify({ Files.readString(any(Path::class.java)) }, never())
            fm.verify({
                Files.writeString(
                    any(Path::class.java), anyString(),
                    any(OpenOption::class.java)
                )
            }, never())
        }
    }

    @Test
    fun existingUidEntryIsSkippedNotDuplicated() {
        // If /etc/passwd already lists the uid (e.g. busybox's "root:x:0:0"),
        // we MUST NOT append a second line. Idempotency matters because hooks
        // can re-trigger ensure().
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/passwd"))) }
                .thenReturn("root:x:0:0:root:/root:/bin/sh\n")
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/group"))) }
                .thenReturn("root:x:0:\n")

            UserDb.ensure(user(0, 0))

            fm.verify({
                Files.writeString(
                    any(Path::class.java), anyString(),
                    any(OpenOption::class.java)
                )
            }, never())
        }
    }

    @Test
    fun missingUidEntryIsAppendedToPasswd() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/passwd"))) }
                .thenReturn("root:x:0:0:root:/root:/bin/sh\n")
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/group"))) }
                .thenReturn("root:x:0:\n")
            fm.`when`<Path> {
                Files.writeString(
                    any(Path::class.java), anyString(),
                    any(OpenOption::class.java)
                )
            }.thenReturn(Path.of("/dev/null"))

            UserDb.ensure(user(1000, 1000))

            // The entry shape is hard-coded to "container:x:<uid>:<gid>:container user:/:/sbin/nologin\n".
            // It's intentional that the shell is /sbin/nologin -- runtime-tools doesn't run anything
            // under this account, it just needs the lookup to succeed.
            fm.verify {
                Files.writeString(
                    eq(Path.of("/etc/passwd")),
                    eq("container:x:1000:1000:container user:/:/sbin/nologin\n"),
                    any(OpenOption::class.java)
                )
            }
        }
    }

    @Test
    fun missingGidEntryIsAppendedToGroup() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            // /etc/passwd already has the uid -> no passwd write
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/passwd"))) }
                .thenReturn("container:x:1000:1000:c:/:/sbin/nologin\n")
            // /etc/group lacks gid=1000 -> append
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/group"))) }
                .thenReturn("root:x:0:\n")
            fm.`when`<Path> {
                Files.writeString(
                    any(Path::class.java), anyString(),
                    any(OpenOption::class.java)
                )
            }.thenReturn(Path.of("/dev/null"))

            UserDb.ensure(user(1000, 1000))

            fm.verify {
                Files.writeString(
                    eq(Path.of("/etc/group")),
                    eq("user:x:1000:\n"),
                    any(OpenOption::class.java)
                )
            }
            fm.verify({
                Files.writeString(
                    eq(Path.of("/etc/passwd")),
                    anyString(), any(OpenOption::class.java)
                )
            }, never())
        }
    }

    @Test
    fun additionalGidsAreAppendedExceptDuplicateOfPrimaryGid() {
        // additionalGids is supplementary. If one of them is == primary gid,
        // we must NOT emit "extra<gid>" for it (else two lines for the same gid).
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/passwd"))) }
                .thenReturn("container:x:1000:1000:c:/:/sbin/nologin\n")
            fm.`when`<String> { Files.readString(eq(Path.of("/etc/group"))) }
                .thenReturn("")
            fm.`when`<Path> {
                Files.writeString(
                    any(Path::class.java), anyString(),
                    any(OpenOption::class.java)
                )
            }.thenReturn(Path.of("/dev/null"))

            val u = user(1000, 1000).copy(additionalGids = listOf(1000, 100, 200))
            UserDb.ensure(u)

            // All missing entries land in ONE append. Primary gid=1000 appears
            // once via the "user" entry and must NOT come back as "extra1000";
            // the non-duplicate supplementary gids do get appended.
            fm.verify {
                Files.writeString(
                    eq(Path.of("/etc/group")),
                    eq("user:x:1000:\nextra100:x:100:\nextra200:x:200:\n"),
                    any(OpenOption::class.java)
                )
            }
            fm.verify({
                Files.writeString(
                    eq(Path.of("/etc/group")),
                    anyString(), any(OpenOption::class.java)
                )
            }, times(1))
        }
    }

    @Test
    fun readFailureIsLoggedNotPropagated() {
        // If /etc/passwd is symlinked weirdly or sealed, Files.readString throws.
        // The runtime must NOT die -- UserDb is a best-effort convenience.
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            fm.`when`<String> { Files.readString(any(Path::class.java)) }
                .thenThrow(IOException("EACCES"))

            assertDoesNotThrow { UserDb.ensure(user(1000, 1000)) }
        }
    }
}
