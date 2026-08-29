package com.ternbusty.takoyaki.spec

import com.ternbusty.takoyaki.util.json.JsonMap

/**
 * OCI runtime-spec bean. Field names match the spec verbatim; codecs are
 * hand-written `fromJson` / `toJson` pairs that walk a
 * [JsonMap] tree. No jackson, no reflection — eliminates ~3,000
 * reachable methods and ~4.6 MB of java.xml at native-image build time
 * vs jackson-databind.
 *
 * Unknown JSON keys are silently ignored (mirrors jackson's
 * `FAIL_ON_UNKNOWN_PROPERTIES=false`). Null fields are dropped from
 * output (mirrors `Include.NON_NULL`).
 */
class Spec {
    var ociVersion: String = "1.0.0"
    var root: Root? = null
    var process: Process? = null
    var hostname: String? = null
    var domainname: String? = null
    var linux: Linux? = null
    var mounts: List<Mount>? = null
    var hooks: Hooks? = null
    var annotations: Map<String, String>? = null

    fun hasNamespace(type: String): Boolean {
        val ns = linux?.namespaces ?: return false
        for (n in ns) {
            if (type == n.type) return true
        }
        return false
    }

    /** True when the spec creates a NEW namespace of this type (no .path). */
    fun isCreatingNamespace(type: String): Boolean {
        val ns = linux?.namespaces ?: return false
        for (n in ns) {
            if (type == n.type && n.path.isNullOrEmpty()) return true
        }
        return false
    }

    fun toJson(): Any {
        val o = JsonMap.obj()
        JsonMap.put(o, "ociVersion", ociVersion)
        root?.let { JsonMap.put(o, "root", it.toJson()) }
        process?.let { JsonMap.put(o, "process", it.toJson()) }
        JsonMap.put(o, "hostname", hostname)
        JsonMap.put(o, "domainname", domainname)
        linux?.let { JsonMap.put(o, "linux", it.toJson()) }
        JsonMap.put(o, "mounts", JsonMap.encList(mounts, Mount::toJson))
        hooks?.let { JsonMap.put(o, "hooks", it.toJson()) }
        JsonMap.put(o, "annotations", annotations)
        return o
    }

    companion object {
        @JvmStatic
        fun fromJson(node: Any?): Spec? {
            if (node == null) return null
            val o = JsonMap.asObject(node) ?: return null
            val s = Spec()
            val v = JsonMap.str(o, "ociVersion")
            if (v != null) s.ociVersion = v
            s.root = Root.fromJson(o["root"])
            s.process = Process.fromJson(o["process"])
            s.hostname = JsonMap.str(o, "hostname")
            s.domainname = JsonMap.str(o, "domainname")
            s.linux = Linux.fromJson(o["linux"])
            s.mounts = JsonMap.list(o, "mounts", Mount::fromJson)?.filterNotNull()
            s.hooks = Hooks.fromJson(o["hooks"])
            @Suppress("UNCHECKED_CAST")
            s.annotations = JsonMap.strMap(o, "annotations") as Map<String, String>?
            return s
        }
    }

    class Root {
        var path: String? = null
        var readonly: Boolean = false

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "path", path)
            JsonMap.putAlways(o, "readonly", readonly)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Root? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val r = Root()
                r.path = JsonMap.str(o, "path")
                r.readonly = JsonMap.boolOr(o, "readonly", false)
                return r
            }
        }
    }

    class Process {
        var args: List<String> = emptyList()
        var env: List<String>? = null
        var cwd: String = "/"
        var noNewPrivileges: Boolean? = null
        var user: User = User()
        var capabilities: LinuxCapabilities? = null
        var rlimits: List<POSIXRlimit>? = null
        var umask: Long? = null
        var apparmorProfile: String? = null
        var selinuxLabel: String? = null
        var terminal: Boolean? = null
        var consoleSize: Box? = null
        var oomScoreAdj: Int? = null
        var ioPriority: IOPriority? = null
        var scheduler: Scheduler? = null
        var execCPUAffinity: ExecCPUAffinity? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "args", args)
            JsonMap.put(o, "env", env)
            JsonMap.put(o, "cwd", cwd)
            JsonMap.put(o, "noNewPrivileges", noNewPrivileges)
            user.let { JsonMap.put(o, "user", it.toJson()) }
            capabilities?.let { JsonMap.put(o, "capabilities", it.toJson()) }
            JsonMap.put(o, "rlimits", JsonMap.encList(rlimits, POSIXRlimit::toJson))
            JsonMap.put(o, "umask", umask)
            JsonMap.put(o, "apparmorProfile", apparmorProfile)
            JsonMap.put(o, "selinuxLabel", selinuxLabel)
            JsonMap.put(o, "terminal", terminal)
            consoleSize?.let { JsonMap.put(o, "consoleSize", it.toJson()) }
            JsonMap.put(o, "oomScoreAdj", oomScoreAdj)
            ioPriority?.let { JsonMap.put(o, "ioPriority", it.toJson()) }
            scheduler?.let { JsonMap.put(o, "scheduler", it.toJson()) }
            execCPUAffinity?.let { JsonMap.put(o, "execCPUAffinity", it.toJson()) }
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Process? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val p = Process()
                val a = JsonMap.strList(o, "args")
                if (a != null) p.args = a.filterNotNull()
                p.env = JsonMap.strList(o, "env")?.filterNotNull()
                val c = JsonMap.str(o, "cwd")
                if (c != null) p.cwd = c
                p.noNewPrivileges = JsonMap.boolBoxed(o, "noNewPrivileges")
                val u = User.fromJson(o["user"])
                if (u != null) p.user = u
                p.capabilities = LinuxCapabilities.fromJson(o["capabilities"])
                p.rlimits = JsonMap.list(o, "rlimits", POSIXRlimit::fromJson)?.filterNotNull()
                p.umask = JsonMap.longBoxed(o, "umask")
                p.apparmorProfile = JsonMap.str(o, "apparmorProfile")
                p.selinuxLabel = JsonMap.str(o, "selinuxLabel")
                p.terminal = JsonMap.boolBoxed(o, "terminal")
                p.consoleSize = Box.fromJson(o["consoleSize"])
                p.oomScoreAdj = JsonMap.intBoxed(o, "oomScoreAdj")
                p.ioPriority = IOPriority.fromJson(o["ioPriority"])
                p.scheduler = Scheduler.fromJson(o["scheduler"])
                p.execCPUAffinity = ExecCPUAffinity.fromJson(o["execCPUAffinity"])
                return p
            }
        }
    }

    class IOPriority {
        var clazz: String? = null
        var priority: Int = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "class", clazz)
            JsonMap.putAlways(o, "priority", priority)
            return o
        }

        /** Map the OCI class string to the kernel constant. */
        fun classValue(): Int {
            if (clazz == null) return 2 // IOPRIO_CLASS_BE
            return when (clazz) {
                "IOPRIO_CLASS_RT" -> 1
                "IOPRIO_CLASS_BE" -> 2
                "IOPRIO_CLASS_IDLE" -> 3
                else -> 2
            }
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): IOPriority? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val p = IOPriority()
                p.clazz = JsonMap.str(o, "class")
                p.priority = JsonMap.intOr(o, "priority", 0)
                return p
            }
        }
    }

    class Scheduler {
        var policy: String? = null
        var nice: Int? = null
        var priority: Int? = null
        var flags: List<String>? = null
        var runtime: Long? = null
        var deadline: Long? = null
        var period: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "policy", policy)
            JsonMap.put(o, "nice", nice)
            JsonMap.put(o, "priority", priority)
            JsonMap.put(o, "flags", flags)
            JsonMap.put(o, "runtime", runtime)
            JsonMap.put(o, "deadline", deadline)
            JsonMap.put(o, "period", period)
            return o
        }

        /** Map the OCI policy string to the kernel constant. */
        fun policyValue(): Int {
            if (policy == null) return 0 // SCHED_OTHER
            return when (policy) {
                "SCHED_OTHER" -> 0
                "SCHED_FIFO" -> 1
                "SCHED_RR" -> 2
                "SCHED_BATCH" -> 3
                "SCHED_ISO" -> 4
                "SCHED_IDLE" -> 5
                "SCHED_DEADLINE" -> 6
                else -> 0
            }
        }

        /** Combine flag strings into a bitmask. */
        fun flagBits(): Long {
            if (flags == null) return 0
            var bits = 0L
            for (f in flags!!) {
                bits = bits or when (f) {
                    "SCHED_FLAG_RESET_ON_FORK" -> 0x01L
                    "SCHED_FLAG_RECLAIM" -> 0x02L
                    "SCHED_FLAG_DL_OVERRUN" -> 0x04L
                    "SCHED_FLAG_KEEP_POLICY" -> 0x08L
                    "SCHED_FLAG_KEEP_PARAMS" -> 0x10L
                    "SCHED_FLAG_UTIL_CLAMP_MIN" -> 0x20L
                    "SCHED_FLAG_UTIL_CLAMP_MAX" -> 0x40L
                    else -> 0L
                }
            }
            return bits
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Scheduler? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val s = Scheduler()
                s.policy = JsonMap.str(o, "policy")
                s.nice = JsonMap.intBoxed(o, "nice")
                s.priority = JsonMap.intBoxed(o, "priority")
                s.flags = JsonMap.strList(o, "flags")?.filterNotNull()
                s.runtime = JsonMap.longBoxed(o, "runtime")
                s.deadline = JsonMap.longBoxed(o, "deadline")
                s.period = JsonMap.longBoxed(o, "period")
                return s
            }
        }
    }

    class ExecCPUAffinity {
        var initial: String? = null
        var fin: String? = null  // maps to JSON key "final"

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "initial", initial)
            JsonMap.put(o, "final", fin)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): ExecCPUAffinity? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val a = ExecCPUAffinity()
                a.initial = JsonMap.str(o, "initial")
                a.fin = JsonMap.str(o, "final")
                return a
            }

            /** Parse a Linux CPU list string (e.g. "0-3,5,7") into a bitmask. */
            @JvmStatic
            fun parseCpuList(list: String?): Long {
                if (list.isNullOrEmpty()) return 0
                var mask = 0L
                for (part in list.split(",")) {
                    val trimmed = part.trim()
                    val dash = trimmed.indexOf('-')
                    if (dash >= 0) {
                        val lo = trimmed.substring(0, dash).trim().toInt()
                        val hi = trimmed.substring(dash + 1).trim().toInt()
                        for (i in lo..hi) {
                            if (i >= 64) break
                            mask = mask or (1L shl i)
                        }
                    } else {
                        val cpu = trimmed.toInt()
                        if (cpu < 64) mask = mask or (1L shl cpu)
                    }
                }
                return mask
            }
        }
    }

    class Box {
        var height: Int = 0
        var width: Int = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "height", height)
            JsonMap.putAlways(o, "width", width)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Box? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val b = Box()
                b.height = JsonMap.intOr(o, "height", 0)
                b.width = JsonMap.intOr(o, "width", 0)
                return b
            }
        }
    }

    class Hook {
        var path: String? = null
        var args: List<String>? = null
        var env: List<String>? = null
        var timeout: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "path", path)
            JsonMap.put(o, "args", args)
            JsonMap.put(o, "env", env)
            JsonMap.put(o, "timeout", timeout)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Hook? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val h = Hook()
                h.path = JsonMap.str(o, "path")
                h.args = JsonMap.strList(o, "args")?.filterNotNull()
                h.env = JsonMap.strList(o, "env")?.filterNotNull()
                h.timeout = JsonMap.longBoxed(o, "timeout")
                return h
            }
        }
    }

    class Hooks {
        var prestart: List<Hook>? = null
        var createRuntime: List<Hook>? = null
        var createContainer: List<Hook>? = null
        var startContainer: List<Hook>? = null
        var poststart: List<Hook>? = null
        var poststop: List<Hook>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "prestart", JsonMap.encList(prestart, Hook::toJson))
            JsonMap.put(o, "createRuntime", JsonMap.encList(createRuntime, Hook::toJson))
            JsonMap.put(o, "createContainer", JsonMap.encList(createContainer, Hook::toJson))
            JsonMap.put(o, "startContainer", JsonMap.encList(startContainer, Hook::toJson))
            JsonMap.put(o, "poststart", JsonMap.encList(poststart, Hook::toJson))
            JsonMap.put(o, "poststop", JsonMap.encList(poststop, Hook::toJson))
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Hooks? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val h = Hooks()
                h.prestart = JsonMap.list(o, "prestart", Hook::fromJson)?.filterNotNull()
                h.createRuntime = JsonMap.list(o, "createRuntime", Hook::fromJson)?.filterNotNull()
                h.createContainer = JsonMap.list(o, "createContainer", Hook::fromJson)?.filterNotNull()
                h.startContainer = JsonMap.list(o, "startContainer", Hook::fromJson)?.filterNotNull()
                h.poststart = JsonMap.list(o, "poststart", Hook::fromJson)?.filterNotNull()
                h.poststop = JsonMap.list(o, "poststop", Hook::fromJson)?.filterNotNull()
                return h
            }
        }
    }

    class User {
        var uid: Int = 0
        var gid: Int = 0
        var additionalGids: List<Int>? = null
        var umask: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "uid", uid)
            JsonMap.putAlways(o, "gid", gid)
            JsonMap.put(o, "additionalGids", additionalGids)
            JsonMap.put(o, "umask", umask)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): User? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val u = User()
                u.uid = JsonMap.intOr(o, "uid", 0)
                u.gid = JsonMap.intOr(o, "gid", 0)
                u.additionalGids = JsonMap.intList(o, "additionalGids")
                u.umask = JsonMap.longBoxed(o, "umask")
                return u
            }
        }
    }

    class POSIXRlimit {
        var type: String? = null
        var hard: Long = 0
        var soft: Long = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "type", type)
            JsonMap.putAlways(o, "hard", hard)
            JsonMap.putAlways(o, "soft", soft)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): POSIXRlimit? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val r = POSIXRlimit()
                r.type = JsonMap.str(o, "type")
                r.hard = JsonMap.longOr(o, "hard", 0)
                r.soft = JsonMap.longOr(o, "soft", 0)
                return r
            }
        }
    }

    class LinuxCapabilities {
        var bounding: List<String>? = null
        var effective: List<String>? = null
        var inheritable: List<String>? = null
        var permitted: List<String>? = null
        var ambient: List<String>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "bounding", bounding)
            JsonMap.put(o, "effective", effective)
            JsonMap.put(o, "inheritable", inheritable)
            JsonMap.put(o, "permitted", permitted)
            JsonMap.put(o, "ambient", ambient)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxCapabilities? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val c = LinuxCapabilities()
                c.bounding = JsonMap.strList(o, "bounding")?.filterNotNull()
                c.effective = JsonMap.strList(o, "effective")?.filterNotNull()
                c.inheritable = JsonMap.strList(o, "inheritable")?.filterNotNull()
                c.permitted = JsonMap.strList(o, "permitted")?.filterNotNull()
                c.ambient = JsonMap.strList(o, "ambient")?.filterNotNull()
                return c
            }
        }
    }

    class Namespace {
        var type: String? = null
        var path: String? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "type", type)
            JsonMap.put(o, "path", path)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Namespace? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val n = Namespace()
                n.type = JsonMap.str(o, "type")
                n.path = JsonMap.str(o, "path")
                return n
            }
        }
    }

    class IdMapping {
        var containerID: Long = 0
        var hostID: Long = 0
        var size: Long = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "containerID", containerID)
            JsonMap.putAlways(o, "hostID", hostID)
            JsonMap.putAlways(o, "size", size)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): IdMapping? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val m = IdMapping()
                m.containerID = JsonMap.longOr(o, "containerID", 0)
                m.hostID = JsonMap.longOr(o, "hostID", 0)
                m.size = JsonMap.longOr(o, "size", 0)
                return m
            }
        }
    }

    class Mount {
        var destination: String? = null
        var source: String? = null
        var type: String? = null
        var options: List<String>? = null
        var uidMappings: List<IdMapping>? = null
        var gidMappings: List<IdMapping>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "destination", destination)
            JsonMap.put(o, "source", source)
            JsonMap.put(o, "type", type)
            JsonMap.put(o, "options", options)
            JsonMap.put(o, "uidMappings", JsonMap.encList(uidMappings, IdMapping::toJson))
            JsonMap.put(o, "gidMappings", JsonMap.encList(gidMappings, IdMapping::toJson))
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Mount? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val m = Mount()
                m.destination = JsonMap.str(o, "destination")
                m.source = JsonMap.str(o, "source")
                m.type = JsonMap.str(o, "type")
                m.options = JsonMap.strList(o, "options")?.filterNotNull()
                m.uidMappings = JsonMap.list(o, "uidMappings", IdMapping::fromJson)?.filterNotNull()
                m.gidMappings = JsonMap.list(o, "gidMappings", IdMapping::fromJson)?.filterNotNull()
                return m
            }
        }
    }

    class LinuxResources {
        var memory: LinuxMemory? = null
        var cpu: LinuxCpu? = null
        var pids: LinuxPids? = null
        var devices: List<LinuxDeviceCgroup>? = null
        var hugepageLimits: List<LinuxHugepageLimit>? = null
        var blockIO: LinuxBlockIO? = null
        /**
         * Free-form cgroup v2 pass-through map. Each key is a control-file name
         * relative to the cgroup directory (e.g. `"io.weight"` or
         * `"hugetlb.2MB.max"`), each value is written verbatim. Lets
         * spec authors reach controllers that aren't modelled by the strongly
         * typed fields above without waiting for takoyaki to grow them.
         */
        var unified: Map<String, String>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            memory?.let { JsonMap.put(o, "memory", it.toJson()) }
            cpu?.let { JsonMap.put(o, "cpu", it.toJson()) }
            pids?.let { JsonMap.put(o, "pids", it.toJson()) }
            JsonMap.put(o, "devices", JsonMap.encList(devices, LinuxDeviceCgroup::toJson))
            JsonMap.put(o, "hugepageLimits",
                    JsonMap.encList(hugepageLimits, LinuxHugepageLimit::toJson))
            blockIO?.let { JsonMap.put(o, "blockIO", it.toJson()) }
            val u = unified
            if (u != null && u.isNotEmpty()) JsonMap.put(o, "unified", u)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxResources? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val r = LinuxResources()
                r.memory = LinuxMemory.fromJson(o["memory"])
                r.cpu = LinuxCpu.fromJson(o["cpu"])
                r.pids = LinuxPids.fromJson(o["pids"])
                r.devices = JsonMap.list(o, "devices", LinuxDeviceCgroup::fromJson)?.filterNotNull()
                r.hugepageLimits = JsonMap.list(o, "hugepageLimits", LinuxHugepageLimit::fromJson)?.filterNotNull()
                r.blockIO = LinuxBlockIO.fromJson(o["blockIO"])
                @Suppress("UNCHECKED_CAST")
                r.unified = JsonMap.strMap(o, "unified") as Map<String, String>?
                return r
            }
        }
    }

    class LinuxHugepageLimit {
        /** e.g. "2MB", "1GB". Matches cgroup v2's hugetlb.<size>.max naming. */
        var pageSize: String? = null
        var limit: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "pageSize", pageSize)
            JsonMap.put(o, "limit", limit)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxHugepageLimit? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val h = LinuxHugepageLimit()
                h.pageSize = JsonMap.str(o, "pageSize")
                h.limit = JsonMap.longBoxed(o, "limit")
                return h
            }
        }
    }

    class LinuxBlockIO {
        /** Default weight, 10..1000. Maps to cgroup v2 io.weight. */
        var weight: Long? = null
        var throttleReadBpsDevice: List<LinuxThrottleDevice>? = null
        var throttleWriteBpsDevice: List<LinuxThrottleDevice>? = null
        var throttleReadIOPSDevice: List<LinuxThrottleDevice>? = null
        var throttleWriteIOPSDevice: List<LinuxThrottleDevice>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "weight", weight)
            JsonMap.put(o, "throttleReadBpsDevice",
                    JsonMap.encList(throttleReadBpsDevice, LinuxThrottleDevice::toJson))
            JsonMap.put(o, "throttleWriteBpsDevice",
                    JsonMap.encList(throttleWriteBpsDevice, LinuxThrottleDevice::toJson))
            JsonMap.put(o, "throttleReadIOPSDevice",
                    JsonMap.encList(throttleReadIOPSDevice, LinuxThrottleDevice::toJson))
            JsonMap.put(o, "throttleWriteIOPSDevice",
                    JsonMap.encList(throttleWriteIOPSDevice, LinuxThrottleDevice::toJson))
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxBlockIO? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val b = LinuxBlockIO()
                b.weight = JsonMap.longBoxed(o, "weight")
                b.throttleReadBpsDevice = JsonMap.list(o,
                        "throttleReadBpsDevice", LinuxThrottleDevice::fromJson)?.filterNotNull()
                b.throttleWriteBpsDevice = JsonMap.list(o,
                        "throttleWriteBpsDevice", LinuxThrottleDevice::fromJson)?.filterNotNull()
                b.throttleReadIOPSDevice = JsonMap.list(o,
                        "throttleReadIOPSDevice", LinuxThrottleDevice::fromJson)?.filterNotNull()
                b.throttleWriteIOPSDevice = JsonMap.list(o,
                        "throttleWriteIOPSDevice", LinuxThrottleDevice::fromJson)?.filterNotNull()
                return b
            }
        }
    }

    class LinuxThrottleDevice {
        var major: Long? = null
        var minor: Long? = null
        /** bytes/sec for *BpsDevice, IOPS for *IOPSDevice. */
        var rate: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "major", major)
            JsonMap.put(o, "minor", minor)
            JsonMap.put(o, "rate", rate)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxThrottleDevice? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val d = LinuxThrottleDevice()
                d.major = JsonMap.longBoxed(o, "major")
                d.minor = JsonMap.longBoxed(o, "minor")
                d.rate = JsonMap.longBoxed(o, "rate")
                return d
            }
        }
    }

    class LinuxMemory {
        var limit: Long? = null
        var reservation: Long? = null
        var swap: Long? = null
        var checkBeforeUpdate: Boolean? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "limit", limit)
            JsonMap.put(o, "reservation", reservation)
            JsonMap.put(o, "swap", swap)
            JsonMap.put(o, "checkBeforeUpdate", checkBeforeUpdate)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxMemory? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val m = LinuxMemory()
                m.limit = JsonMap.longBoxed(o, "limit")
                m.reservation = JsonMap.longBoxed(o, "reservation")
                m.swap = JsonMap.longBoxed(o, "swap")
                m.checkBeforeUpdate = JsonMap.boolBoxed(o, "checkBeforeUpdate")
                return m
            }
        }
    }

    class LinuxCpu {
        var shares: Long? = null
        var quota: Long? = null
        var period: Long? = null
        var cpus: String? = null
        var mems: String? = null
        var realtimePeriod: Long? = null
        var realtimeRuntime: Long? = null
        /** Linux 5.14+ CPU burst window in the same units as quota. */
        var burst: Long? = null
        /** 1 -> SCHED_IDLE cgroup (best-effort scheduling). Linux 5.15+. */
        var idle: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "shares", shares)
            JsonMap.put(o, "quota", quota)
            JsonMap.put(o, "period", period)
            JsonMap.put(o, "cpus", cpus)
            JsonMap.put(o, "mems", mems)
            JsonMap.put(o, "realtimePeriod", realtimePeriod)
            JsonMap.put(o, "realtimeRuntime", realtimeRuntime)
            JsonMap.put(o, "burst", burst)
            JsonMap.put(o, "idle", idle)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxCpu? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val c = LinuxCpu()
                c.shares = JsonMap.longBoxed(o, "shares")
                c.quota = JsonMap.longBoxed(o, "quota")
                c.period = JsonMap.longBoxed(o, "period")
                c.cpus = JsonMap.str(o, "cpus")
                c.mems = JsonMap.str(o, "mems")
                c.realtimePeriod = JsonMap.longBoxed(o, "realtimePeriod")
                c.realtimeRuntime = JsonMap.longBoxed(o, "realtimeRuntime")
                c.burst = JsonMap.longBoxed(o, "burst")
                c.idle = JsonMap.longBoxed(o, "idle")
                return c
            }
        }
    }

    class LinuxPids {
        var limit: Long = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "limit", limit)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxPids? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val p = LinuxPids()
                p.limit = JsonMap.longOr(o, "limit", 0)
                return p
            }
        }
    }

    class SeccompArg {
        var index: Int = 0
        var value: Long = 0
        var valueTwo: Long? = null
        var op: String? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "index", index)
            JsonMap.putAlways(o, "value", value)
            JsonMap.put(o, "valueTwo", valueTwo)
            JsonMap.put(o, "op", op)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): SeccompArg? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val a = SeccompArg()
                a.index = JsonMap.intOr(o, "index", 0)
                a.value = JsonMap.longOr(o, "value", 0)
                a.valueTwo = JsonMap.longBoxed(o, "valueTwo")
                a.op = JsonMap.str(o, "op")
                return a
            }
        }
    }

    class LinuxSyscall {
        var names: List<String>? = null
        var action: String? = null
        var errnoRet: Long? = null
        var args: List<SeccompArg>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "names", names)
            JsonMap.put(o, "action", action)
            JsonMap.put(o, "errnoRet", errnoRet)
            JsonMap.put(o, "args", JsonMap.encList(args, SeccompArg::toJson))
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxSyscall? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val s = LinuxSyscall()
                s.names = JsonMap.strList(o, "names")?.filterNotNull()
                s.action = JsonMap.str(o, "action")
                s.errnoRet = JsonMap.longBoxed(o, "errnoRet")
                s.args = JsonMap.list(o, "args", SeccompArg::fromJson)?.filterNotNull()
                return s
            }
        }
    }

    class LinuxSeccomp {
        var defaultAction: String? = null
        var defaultErrnoRet: Long? = null
        var architectures: List<String>? = null
        var syscalls: List<LinuxSyscall>? = null
        var flags: List<String>? = null
        var listenerPath: String? = null
        var listenerMetadata: String? = null

        /** True when any syscall rule uses SCMP_ACT_NOTIFY. */
        fun hasNotifyAction(): Boolean {
            val sc = syscalls ?: return false
            for (s in sc) {
                if ("SCMP_ACT_NOTIFY" == s.action) return true
            }
            return false
        }

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "defaultAction", defaultAction)
            JsonMap.put(o, "defaultErrnoRet", defaultErrnoRet)
            JsonMap.put(o, "architectures", architectures)
            JsonMap.put(o, "syscalls", JsonMap.encList(syscalls, LinuxSyscall::toJson))
            JsonMap.put(o, "flags", flags)
            JsonMap.put(o, "listenerPath", listenerPath)
            JsonMap.put(o, "listenerMetadata", listenerMetadata)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxSeccomp? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val s = LinuxSeccomp()
                s.defaultAction = JsonMap.str(o, "defaultAction")
                s.defaultErrnoRet = JsonMap.longBoxed(o, "defaultErrnoRet")
                s.architectures = JsonMap.strList(o, "architectures")?.filterNotNull()
                s.syscalls = JsonMap.list(o, "syscalls", LinuxSyscall::fromJson)?.filterNotNull()
                s.flags = JsonMap.strList(o, "flags")?.filterNotNull()
                s.listenerPath = JsonMap.str(o, "listenerPath")
                s.listenerMetadata = JsonMap.str(o, "listenerMetadata")
                return s
            }
        }
    }

    class LinuxDevice {
        var path: String? = null
        var type: String? = null
        var major: Long? = null
        var minor: Long? = null
        var fileMode: Long? = null
        var uid: Long? = null
        var gid: Long? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "path", path)
            JsonMap.put(o, "type", type)
            JsonMap.put(o, "major", major)
            JsonMap.put(o, "minor", minor)
            JsonMap.put(o, "fileMode", fileMode)
            JsonMap.put(o, "uid", uid)
            JsonMap.put(o, "gid", gid)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxDevice? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val d = LinuxDevice()
                d.path = JsonMap.str(o, "path")
                d.type = JsonMap.str(o, "type")
                d.major = JsonMap.longBoxed(o, "major")
                d.minor = JsonMap.longBoxed(o, "minor")
                d.fileMode = JsonMap.longBoxed(o, "fileMode")
                d.uid = JsonMap.longBoxed(o, "uid")
                d.gid = JsonMap.longBoxed(o, "gid")
                return d
            }
        }
    }

    class LinuxDeviceCgroup {
        var allow: Boolean = false
        var type: String? = null
        var major: Long? = null
        var minor: Long? = null
        var access: String? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "allow", allow)
            JsonMap.put(o, "type", type)
            JsonMap.put(o, "major", major)
            JsonMap.put(o, "minor", minor)
            JsonMap.put(o, "access", access)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): LinuxDeviceCgroup? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val d = LinuxDeviceCgroup()
                d.allow = JsonMap.boolOr(o, "allow", false)
                d.type = JsonMap.str(o, "type")
                d.major = JsonMap.longBoxed(o, "major")
                d.minor = JsonMap.longBoxed(o, "minor")
                d.access = JsonMap.str(o, "access")
                return d
            }
        }
    }

    class TimeOffset {
        var secs: Long = 0
        var nanosecs: Long = 0

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.putAlways(o, "secs", secs)
            JsonMap.putAlways(o, "nanosecs", nanosecs)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): TimeOffset? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val t = TimeOffset()
                t.secs = JsonMap.longOr(o, "secs", 0)
                t.nanosecs = JsonMap.longOr(o, "nanosecs", 0)
                return t
            }
        }
    }

    class Linux {
        var namespaces: List<Namespace>? = null
        var uidMappings: List<IdMapping>? = null
        var gidMappings: List<IdMapping>? = null
        var resources: LinuxResources? = null
        var cgroupsPath: String? = null
        var seccomp: LinuxSeccomp? = null
        var devices: List<LinuxDevice>? = null
        var maskedPaths: List<String>? = null
        var readonlyPaths: List<String>? = null
        var rootfsPropagation: String? = null
        var sysctl: Map<String, String>? = null
        var timeOffsets: Map<String, TimeOffset>? = null
        var memoryPolicy: MemoryPolicy? = null
        var netDevices: Map<String, NetDevice>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "namespaces", JsonMap.encList(namespaces, Namespace::toJson))
            JsonMap.put(o, "uidMappings", JsonMap.encList(uidMappings, IdMapping::toJson))
            JsonMap.put(o, "gidMappings", JsonMap.encList(gidMappings, IdMapping::toJson))
            resources?.let { JsonMap.put(o, "resources", it.toJson()) }
            JsonMap.put(o, "cgroupsPath", cgroupsPath)
            seccomp?.let { JsonMap.put(o, "seccomp", it.toJson()) }
            JsonMap.put(o, "devices", JsonMap.encList(devices, LinuxDevice::toJson))
            JsonMap.put(o, "maskedPaths", maskedPaths)
            JsonMap.put(o, "readonlyPaths", readonlyPaths)
            JsonMap.put(o, "rootfsPropagation", rootfsPropagation)
            JsonMap.put(o, "sysctl", sysctl)
            memoryPolicy?.let { JsonMap.put(o, "memoryPolicy", it.toJson()) }
            netDevices?.let { nd ->
                val m = JsonMap.obj()
                for ((key, value) in nd) {
                    m[key] = value.toJson()
                }
                JsonMap.put(o, "netDevices", m)
            }
            timeOffsets?.let { to ->
                val m = JsonMap.obj()
                for ((key, value) in to) {
                    m[key] = value.toJson()
                }
                JsonMap.put(o, "timeOffsets", m)
            }
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): Linux? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val l = Linux()
                l.namespaces = JsonMap.list(o, "namespaces", Namespace::fromJson)?.filterNotNull()
                l.uidMappings = JsonMap.list(o, "uidMappings", IdMapping::fromJson)?.filterNotNull()
                l.gidMappings = JsonMap.list(o, "gidMappings", IdMapping::fromJson)?.filterNotNull()
                l.resources = LinuxResources.fromJson(o["resources"])
                l.cgroupsPath = JsonMap.str(o, "cgroupsPath")
                l.seccomp = LinuxSeccomp.fromJson(o["seccomp"])
                l.devices = JsonMap.list(o, "devices", LinuxDevice::fromJson)?.filterNotNull()
                l.maskedPaths = JsonMap.strList(o, "maskedPaths")?.filterNotNull()
                l.readonlyPaths = JsonMap.strList(o, "readonlyPaths")?.filterNotNull()
                l.rootfsPropagation = JsonMap.str(o, "rootfsPropagation")
                @Suppress("UNCHECKED_CAST")
                l.sysctl = JsonMap.strMap(o, "sysctl") as Map<String, String>?
                @Suppress("UNCHECKED_CAST")
                l.timeOffsets = JsonMap.map(o, "timeOffsets", TimeOffset::fromJson)
                        ?.filterValues { it != null } as Map<String, TimeOffset>?
                l.memoryPolicy = MemoryPolicy.fromJson(o["memoryPolicy"])
                @Suppress("UNCHECKED_CAST")
                l.netDevices = JsonMap.map(o, "netDevices", NetDevice::fromJson)
                        ?.filterValues { it != null } as Map<String, NetDevice>?
                return l
            }
        }
    }

    /** NUMA memory policy (linux.memoryPolicy). */
    class MemoryPolicy {
        var mode: String? = null
        var nodes: String? = null
        var flags: List<String>? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "mode", mode)
            JsonMap.put(o, "nodes", nodes)
            JsonMap.put(o, "flags", flags)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): MemoryPolicy? {
                if (node == null) return null
                val o = JsonMap.asObject(node) ?: return null
                val m = MemoryPolicy()
                m.mode = JsonMap.str(o, "mode")
                m.nodes = JsonMap.str(o, "nodes")
                m.flags = JsonMap.strList(o, "flags")?.filterNotNull()
                return m
            }
        }
    }

    /** Network device to move into the container namespace (linux.netDevices). */
    class NetDevice {
        var name: String? = null

        fun toJson(): Any {
            val o = JsonMap.obj()
            JsonMap.put(o, "name", name)
            return o
        }

        companion object {
            @JvmStatic
            fun fromJson(node: Any?): NetDevice? {
                if (node == null) return NetDevice()
                val o = JsonMap.asObject(node) ?: return null
                val d = NetDevice()
                d.name = JsonMap.str(o, "name")
                return d
            }
        }
    }
}
