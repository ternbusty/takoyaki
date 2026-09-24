package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * devMountFlags picks the options of the spec's /dev mount. Its MS_RDONLY is
 * what decides whether remountDevReadonly makes /dev read-only after setup.
 */
class RootfsDevMountFlagsTest {

    private static Spec.Mount mount(String destination, String... options) {
        Spec.Mount m = new Spec.Mount();
        m.destination = destination;
        m.type = "tmpfs";
        m.source = "tmpfs";
        m.options = List.of(options);
        return m;
    }

    private static Spec spec(Spec.Mount... mounts) {
        Spec s = new Spec();
        s.mounts = List.of(mounts);
        return s;
    }

    @Test
    void readonlyDevMountSetsRdonly() {
        long flags = Rootfs.devMountFlags(spec(
                mount("/proc"),
                mount("/dev", "nosuid", "strictatime", "mode=755", "size=65536k", "ro")));
        assertEquals(Constants.MS_RDONLY, flags & Constants.MS_RDONLY);
        assertEquals(Constants.MS_NOSUID, flags & Constants.MS_NOSUID);
    }

    @Test
    void writableDevMountHasNoRdonly() {
        long flags = Rootfs.devMountFlags(spec(mount("/dev", "nosuid", "mode=755")));
        assertEquals(0, flags & Constants.MS_RDONLY);
    }

    @Test
    void readonlyMountElsewhereDoesNotCount() {
        assertEquals(0, Rootfs.devMountFlags(spec(mount("/dev/shm", "ro"))));
    }

    @Test
    void noMountsMeansNoFlags() {
        assertEquals(0, Rootfs.devMountFlags(new Spec()));
    }
}
