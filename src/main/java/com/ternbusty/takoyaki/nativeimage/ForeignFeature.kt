package com.ternbusty.takoyaki.nativeimage

import org.graalvm.nativeimage.hosted.Feature
import org.graalvm.nativeimage.hosted.Feature.DuringSetupAccess
import org.graalvm.nativeimage.hosted.RuntimeForeignAccess

import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.ValueLayout

class ForeignFeature : Feature {

    override fun duringSetup(access: DuringSetupAccess) {
        // Register all downcall signatures we use in PosixIO + Libc + seccomp + ipc.

        // int->int
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT))
        // ()->int  (getpid, getppid, fork, clearenv)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT))
        // void ()
        reg(FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT))
        // ()->ptr   (__errno_location)
        reg(FunctionDescriptor.of(ValueLayout.ADDRESS))
        // (int)->ptr  (strerror)
        reg(FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
        // (int,int)->int  (kill, listen, fchdir, setns)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT))
        // (int,int,int)->int  (socket)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
            )
        )
        // (int,int,int,ptr)->int  (socketpair)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS
            )
        )
        // (int,ptr,int)->int  (bind, connect; waitpid shares this descriptor)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT
            )
        )
        // (int,ptr,ptr)->int  (accept)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS
            )
        )
        // (int,ptr,long)->long  (read, write)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG
            )
        )
        // (int,ptr,long,int)->long  (send, recv)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT
            )
        )
        // (ptr)->int  (chdir, unlink)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
        // (ptr,int)->int  (access)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
        // (ptr,int,int)->int  (open)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
            )
        )
        // (ptr,ptr)->int  (pivot_root, execvp)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
        // (ptr,ptr,ptr)->int  (execve)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS
            )
        )
        // (ptr,ptr,long)->long  (readlink)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG
            )
        )
        // (ptr,ptr,ptr,long,ptr)->int  (mount)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG, ValueLayout.ADDRESS
            )
        )
        // (ptr,int)->int  (umount2 - already covered above)
        // (ptr,long)->int  (sethostname)
        reg(FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG))
        // (int,long,long,long,long)->int  (prctl)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG
            )
        )
        // (ptr,ptr,int)->int  (setenv)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT
            )
        )

        // (long,ptr)->int  (setgroups)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_LONG, ValueLayout.ADDRESS
            )
        )
        // (int,int,ptr,ptr)->int  (prlimit64)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS
            )
        )
        // (long,long,long,long,long,long)->long  (syscall(SYS_X, ...))
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG
            )
        )

        // seccomp downcalls
        // (int)->ptr  (seccomp_init)
        reg(FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
        // void(ptr)  (seccomp_release)
        reg(FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
        // (ptr,int,int,int)->int  (seccomp_rule_add)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT
            )
        )
        // (int,int,int)->int  (setresuid / setresgid)
        // already covered above by socket() signature
        // (ptr,int,long)->int  (mknod)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG
            )
        )
        // (int,long,ptr)->int  (ioctl)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS
            )
        )
        // (int,ptr,long)->int  (ptsname_r)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG
            )
        )
        // (int,ptr,int)->long  (sendmsg / recvmsg)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT
            )
        )
        // (ptr,int,int,int,ptr)->int  (seccomp_rule_add_array)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS
            )
        )
        // (ptr,int,long)->int  (seccomp_attr_set)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG
            )
        )
        // (ptr,int,int)->int  (jextract seccomp_attr_set — uint32_t value)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
            )
        )
        // (ptr,int)->int  (seccomp_arch_add / seccomp_arch_remove)
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT
            )
        )

        // Variadic libc functions reached through jextract's makeInvoker
        // factory (Libc.PRCTL/SYSCALL/IOCTL). firstVariadicArg makes these a
        // distinct registration from a plain descriptor of the same shape.
        // On aarch64 the variadic and non-variadic ABI are identical, so the
        // plain registrations above already work. On x86_64, the SysV ABI
        // treats variadic calls differently (AL = number of SSE args), so
        // these variadic registrations are essential.
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG
            ),
            Linker.Option.firstVariadicArg(1)
        )
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG
            ),
            Linker.Option.firstVariadicArg(1)
        )
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS
            ),
            Linker.Option.firstVariadicArg(2)
        )
        // open(const char *, int flags, ...) with mode_t variadic arg
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
            ),
            Linker.Option.firstVariadicArg(2)
        )
        // fcntl(int fd, int cmd, ...) with int variadic arg
        reg(
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
            ),
            Linker.Option.firstVariadicArg(2)
        )
    }

    companion object {
        private fun reg(desc: FunctionDescriptor, vararg options: Linker.Option) {
            RuntimeForeignAccess.registerForDowncall(desc, *options)
        }

        private fun reg(desc: FunctionDescriptor) {
            RuntimeForeignAccess.registerForDowncall(desc)
        }
    }
}
