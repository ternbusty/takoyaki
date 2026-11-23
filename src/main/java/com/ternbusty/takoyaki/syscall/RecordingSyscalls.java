package com.ternbusty.takoyaki.syscall;

import java.util.ArrayList;
import java.util.List;
import java.util.function.IntSupplier;

/**
 * Test fake that records every {@link Syscalls} call and lets tests pin
 * return values per method. Modelled on youki's {@code TestHelperSyscall},
 * which keeps a {@code MockCalls} map of {@code Vec<Box<dyn Any>>} per
 * call category. We use one ArrayList per method for the same effect with
 * static types.
 *
 * Default return values are "success" (0 for int returns, "ok" for
 * strerror). A test can override per-method with the {@code stub*} methods,
 * or supply an {@link IntSupplier} for sequence-dependent returns.
 */
public final class RecordingSyscalls implements Syscalls {

    // ---- recorded calls -----------------------------------------------------

    public record MountCall(String source, String target, String fstype,
                            long flags, String data) {}
    public record Umount2Call(String target, int flags) {}
    public record KillCall(int pid, int sig) {}
    public record SyscallCall(long nr, long a1, long a2, long a3, long a4, long a5) {}
    public record PrlimitCall(int pid, int resource, long soft, long hard) {}
    public record IfUpCall(String ifaceName) {}
    public record KeyctlJoinCall(String name) {}
    public record MknodCall(String path, int mode, long dev) {}
    public record AccessCall(String path, int mode) {}

    private final List<MountCall>       mountCalls       = new ArrayList<>();
    private final List<MountCall>       rawMountCalls    = new ArrayList<>();
    private final List<Umount2Call>     umount2Calls     = new ArrayList<>();
    private final List<KillCall>        killCalls        = new ArrayList<>();
    private final List<SyscallCall>     syscallCalls     = new ArrayList<>();
    private final List<PrlimitCall>     prlimitCalls     = new ArrayList<>();
    private final List<IfUpCall>        ifUpCalls        = new ArrayList<>();
    private final List<KeyctlJoinCall>  keyctlJoinCalls  = new ArrayList<>();
    private final List<MknodCall>       mknodCalls       = new ArrayList<>();
    private final List<AccessCall>      accessCalls      = new ArrayList<>();

    // ---- stub knobs ---------------------------------------------------------

    private IntSupplier mountReturn      = () -> 0;
    private IntSupplier umount2Return    = () -> 0;
    private IntSupplier killReturn       = () -> 0;
    private long        syscallReturn    = 0L;
    private IntSupplier prlimitReturn    = () -> 0;
    private IntSupplier ifUpReturn       = () -> 0;
    private long        keyctlJoinReturn = 1L;
    private IntSupplier mknodReturn      = () -> 0;
    private IntSupplier accessReturn     = () -> 0;
    private int         errno            = 0;

    // ---- Syscalls impl ------------------------------------------------------

    /**
     * Records source and target as the paths they name: Rootfs mounts on the
     * /proc/thread-self/fd/N of an opened mount point, which is read here
     * while the fd is still open. The arguments as passed are kept in
     * {@link #rawMountCalls}.
     */
    @Override
    public int mount(String source, String target, String fstype, long flags, String data) {
        rawMountCalls.add(new MountCall(source, target, fstype, flags, data));
        mountCalls.add(new MountCall(fdTarget(source), fdTarget(target), fstype, flags, data));
        return mountReturn.getAsInt();
    }

    private static String fdTarget(String path) {
        if (path == null || !path.startsWith("/proc/thread-self/fd/")) return path;
        try {
            return java.nio.file.Files.readSymbolicLink(java.nio.file.Path.of(path)).toString();
        } catch (java.io.IOException e) {
            return path;
        }
    }

    @Override
    public int umount2(String target, int flags) {
        umount2Calls.add(new Umount2Call(target, flags));
        return umount2Return.getAsInt();
    }

    @Override
    public int errno() {
        return errno;
    }

    @Override
    public String strerror(int errnum) {
        return "errno=" + errnum;
    }

    @Override
    public int kill(int pid, int sig) {
        killCalls.add(new KillCall(pid, sig));
        return killReturn.getAsInt();
    }

    @Override
    public long syscall(long nr, long a1, long a2, long a3, long a4, long a5) {
        syscallCalls.add(new SyscallCall(nr, a1, a2, a3, a4, a5));
        return syscallReturn;
    }

    @Override
    public int prlimit64(int pid, int resource, long soft, long hard) {
        prlimitCalls.add(new PrlimitCall(pid, resource, soft, hard));
        return prlimitReturn.getAsInt();
    }

    @Override
    public int ifUp(String ifaceName) {
        ifUpCalls.add(new IfUpCall(ifaceName));
        return ifUpReturn.getAsInt();
    }

    @Override
    public long keyctlJoinSessionKeyring(String name) {
        keyctlJoinCalls.add(new KeyctlJoinCall(name));
        return keyctlJoinReturn;
    }

    @Override
    public int mknod(String path, int mode, long dev) {
        mknodCalls.add(new MknodCall(path, mode, dev));
        return mknodReturn.getAsInt();
    }

    @Override
    public int access(String path, int mode) {
        accessCalls.add(new AccessCall(path, mode));
        return accessReturn.getAsInt();
    }

    // ---- inspection (called from tests) ------------------------------------

    public List<MountCall>      mountCalls()      { return mountCalls; }
    public List<MountCall>      rawMountCalls()   { return rawMountCalls; }
    public List<Umount2Call>    umount2Calls()    { return umount2Calls; }
    public List<KillCall>       killCalls()       { return killCalls; }
    public List<SyscallCall>    syscallCalls()    { return syscallCalls; }
    public List<PrlimitCall>    prlimitCalls()    { return prlimitCalls; }
    public List<IfUpCall>       ifUpCalls()       { return ifUpCalls; }
    public List<KeyctlJoinCall> keyctlJoinCalls() { return keyctlJoinCalls; }
    public List<MknodCall>      mknodCalls()      { return mknodCalls; }
    public List<AccessCall>     accessCalls()     { return accessCalls; }

    // ---- stub setters (called from tests) ----------------------------------

    /** All future mount calls return this value. */
    public RecordingSyscalls stubMountReturn(int rc) {
        this.mountReturn = () -> rc;
        return this;
    }

    /** Sequence-dependent mount return — supplier is called once per mount. */
    public RecordingSyscalls stubMountReturn(IntSupplier seq) {
        this.mountReturn = seq;
        return this;
    }

    public RecordingSyscalls stubUmount2Return(int rc) {
        this.umount2Return = () -> rc;
        return this;
    }

    public RecordingSyscalls stubKillReturn(int rc) {
        this.killReturn = () -> rc;
        return this;
    }

    public RecordingSyscalls stubSyscallReturn(long rc) {
        this.syscallReturn = rc;
        return this;
    }

    public RecordingSyscalls stubPrlimitReturn(int rc) {
        this.prlimitReturn = () -> rc;
        return this;
    }

    /** Sequence-dependent prlimit return — supplier called once per prlimit. */
    public RecordingSyscalls stubPrlimitReturn(IntSupplier seq) {
        this.prlimitReturn = seq;
        return this;
    }

    public RecordingSyscalls stubIfUpReturn(int rc) {
        this.ifUpReturn = () -> rc;
        return this;
    }

    public RecordingSyscalls stubKeyctlJoinReturn(long rc) {
        this.keyctlJoinReturn = rc;
        return this;
    }

    public RecordingSyscalls stubMknodReturn(int rc) {
        this.mknodReturn = () -> rc;
        return this;
    }

    public RecordingSyscalls stubMknodReturn(IntSupplier seq) {
        this.mknodReturn = seq;
        return this;
    }

    public RecordingSyscalls stubAccessReturn(int rc) {
        this.accessReturn = () -> rc;
        return this;
    }

    /** Set the errno value that subsequent errno() calls return. */
    public RecordingSyscalls stubErrno(int errno) {
        this.errno = errno;
        return this;
    }
}
