package com.ternbusty.takoyaki.syscall

import java.util.function.IntSupplier

/**
 * Test fake that records every [Syscalls] call and lets tests pin
 * return values per method. Modelled on youki's `TestHelperSyscall`,
 * which keeps a `MockCalls` map of `Vec<Box<dyn Any>>` per
 * call category. We use one ArrayList per method for the same effect with
 * static types.
 *
 * Default return values are "success" (0 for int returns, "ok" for
 * strerror). A test can override per-method with the `stub*` methods,
 * or supply an [IntSupplier] for sequence-dependent returns.
 */
class RecordingSyscalls : Syscalls {

    // ---- recorded calls -----------------------------------------------------

    data class MountCall(
        val source: String?, val target: String, val fstype: String?,
        val flags: Long, val data: String?,
    )
    data class Umount2Call(val target: String, val flags: Int)
    data class KillCall(val pid: Int, val sig: Int)
    data class SyscallCall(val nr: Long, val a1: Long, val a2: Long, val a3: Long, val a4: Long, val a5: Long)
    data class PrlimitCall(val pid: Int, val resource: Int, val soft: Long, val hard: Long)
    data class IfUpCall(val ifaceName: String)
    data class KeyctlJoinCall(val name: String?)
    data class MknodCall(val path: String, val mode: Int, val dev: Long)
    data class AccessCall(val path: String, val mode: Int)

    private val _mountCalls: MutableList<MountCall> = mutableListOf()
    private val _umount2Calls: MutableList<Umount2Call> = mutableListOf()
    private val _killCalls: MutableList<KillCall> = mutableListOf()
    private val _syscallCalls: MutableList<SyscallCall> = mutableListOf()
    private val _prlimitCalls: MutableList<PrlimitCall> = mutableListOf()
    private val _ifUpCalls: MutableList<IfUpCall> = mutableListOf()
    private val _keyctlJoinCalls: MutableList<KeyctlJoinCall> = mutableListOf()
    private val _mknodCalls: MutableList<MknodCall> = mutableListOf()
    private val _accessCalls: MutableList<AccessCall> = mutableListOf()

    // ---- stub knobs ---------------------------------------------------------

    private var mountReturn: IntSupplier = IntSupplier { 0 }
    private var umount2Return: IntSupplier = IntSupplier { 0 }
    private var killReturn: IntSupplier = IntSupplier { 0 }
    private var syscallReturn: Long = 0L
    private var prlimitReturn: IntSupplier = IntSupplier { 0 }
    private var ifUpReturn: IntSupplier = IntSupplier { 0 }
    private var keyctlJoinReturn: Long = 1L
    private var mknodReturn: IntSupplier = IntSupplier { 0 }
    private var accessReturn: IntSupplier = IntSupplier { 0 }
    private var errno: Int = 0

    // ---- Syscalls impl ------------------------------------------------------

    override fun mount(source: String?, target: String, fstype: String?, flags: Long, data: String?): Int {
        _mountCalls.add(MountCall(source, target, fstype, flags, data))
        return mountReturn.asInt
    }

    override fun umount2(target: String, flags: Int): Int {
        _umount2Calls.add(Umount2Call(target, flags))
        return umount2Return.asInt
    }

    override fun errno(): Int = errno

    override fun strerror(errnum: Int): String = "errno=$errnum"

    override fun kill(pid: Int, sig: Int): Int {
        _killCalls.add(KillCall(pid, sig))
        return killReturn.asInt
    }

    override fun syscall(nr: Long, a1: Long, a2: Long, a3: Long, a4: Long, a5: Long): Long {
        _syscallCalls.add(SyscallCall(nr, a1, a2, a3, a4, a5))
        return syscallReturn
    }

    override fun prlimit64(pid: Int, resource: Int, soft: Long, hard: Long): Int {
        _prlimitCalls.add(PrlimitCall(pid, resource, soft, hard))
        return prlimitReturn.asInt
    }

    override fun ifUp(ifaceName: String): Int {
        _ifUpCalls.add(IfUpCall(ifaceName))
        return ifUpReturn.asInt
    }

    override fun keyctlJoinSessionKeyring(name: String?): Long {
        _keyctlJoinCalls.add(KeyctlJoinCall(name))
        return keyctlJoinReturn
    }

    override fun mknod(path: String, mode: Int, dev: Long): Int {
        _mknodCalls.add(MknodCall(path, mode, dev))
        return mknodReturn.asInt
    }

    override fun access(path: String, mode: Int): Int {
        _accessCalls.add(AccessCall(path, mode))
        return accessReturn.asInt
    }

    // ---- inspection (called from tests) ------------------------------------

    fun mountCalls(): List<MountCall> = _mountCalls
    fun umount2Calls(): List<Umount2Call> = _umount2Calls
    fun killCalls(): List<KillCall> = _killCalls
    fun syscallCalls(): List<SyscallCall> = _syscallCalls
    fun prlimitCalls(): List<PrlimitCall> = _prlimitCalls
    fun ifUpCalls(): List<IfUpCall> = _ifUpCalls
    fun keyctlJoinCalls(): List<KeyctlJoinCall> = _keyctlJoinCalls
    fun mknodCalls(): List<MknodCall> = _mknodCalls
    fun accessCalls(): List<AccessCall> = _accessCalls

    // ---- stub setters (called from tests) ----------------------------------

    /** All future mount calls return this value. */
    fun stubMountReturn(rc: Int): RecordingSyscalls = apply {
        mountReturn = IntSupplier { rc }
    }

    /** Sequence-dependent mount return -- supplier is called once per mount. */
    fun stubMountReturn(seq: IntSupplier): RecordingSyscalls = apply {
        mountReturn = seq
    }

    fun stubUmount2Return(rc: Int): RecordingSyscalls = apply {
        umount2Return = IntSupplier { rc }
    }

    fun stubKillReturn(rc: Int): RecordingSyscalls = apply {
        killReturn = IntSupplier { rc }
    }

    fun stubSyscallReturn(rc: Long): RecordingSyscalls = apply {
        syscallReturn = rc
    }

    fun stubPrlimitReturn(rc: Int): RecordingSyscalls = apply {
        prlimitReturn = IntSupplier { rc }
    }

    /** Sequence-dependent prlimit return -- supplier called once per prlimit. */
    fun stubPrlimitReturn(seq: IntSupplier): RecordingSyscalls = apply {
        prlimitReturn = seq
    }

    fun stubIfUpReturn(rc: Int): RecordingSyscalls = apply {
        ifUpReturn = IntSupplier { rc }
    }

    fun stubKeyctlJoinReturn(rc: Long): RecordingSyscalls = apply {
        keyctlJoinReturn = rc
    }

    fun stubMknodReturn(rc: Int): RecordingSyscalls = apply {
        mknodReturn = IntSupplier { rc }
    }

    fun stubMknodReturn(seq: IntSupplier): RecordingSyscalls = apply {
        mknodReturn = seq
    }

    fun stubAccessReturn(rc: Int): RecordingSyscalls = apply {
        accessReturn = IntSupplier { rc }
    }

    /** Set the errno value that subsequent errno() calls return. */
    fun stubErrno(errno: Int): RecordingSyscalls = apply {
        this.errno = errno
    }
}
