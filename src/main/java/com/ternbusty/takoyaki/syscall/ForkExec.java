package com.ternbusty.takoyaki.syscall;

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
                WordFactory.pointer(payload.getPath().address()),
                WordFactory.pointer(payload.getArgv().address()),
                WordFactory.pointer(payload.getEnvp().address()),
                closeFd1, closeFd2);
    }
}
