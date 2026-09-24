package com.ternbusty.takoyaki.syscall;

import java.lang.foreign.MemorySegment;

import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CCharPointerPointer;
import org.graalvm.word.WordFactory;

public final class ForkExec {
    private ForkExec() {}

    @CFunction("takoyaki_fork_exec")
    private static native int nativeForkExec(CCharPointer path, CCharPointerPointer argv,
                                             CCharPointerPointer envp, int closeFd1, int closeFd2);

    public static int forkExec(PosixIO.ExecvePayload payload, int closeFd1, int closeFd2) {
        return nativeForkExec(
                WordFactory.pointer(payload.path.address()),
                WordFactory.pointer(payload.argv.address()),
                WordFactory.pointer(payload.envp.address()),
                closeFd1, closeFd2);
    }

    @CFunction("takoyaki_fork_exec_into_cgroup")
    private static native int nativeForkExecIntoCgroup(CCharPointer path, CCharPointerPointer argv,
                                                       CCharPointerPointer envp, int closeFd1, int closeFd2,
                                                       CCharPointer cgroupDir);

    /**
     * Fork and exec with the child created directly in the cgroup at
     * cgroupDir (clone3 CLONE_INTO_CGROUP). Returns -1 with errno set, and no
     * child, when that is not possible; the caller then falls back to
     * {@link #forkExec} and writing cgroup.procs.
     */
    public static int forkExecIntoCgroup(PosixIO.ExecvePayload payload, int closeFd1, int closeFd2,
                                         MemorySegment cgroupDir) {
        return nativeForkExecIntoCgroup(
                WordFactory.pointer(payload.path.address()),
                WordFactory.pointer(payload.argv.address()),
                WordFactory.pointer(payload.envp.address()),
                closeFd1, closeFd2,
                WordFactory.pointer(cgroupDir.address()));
    }
}
