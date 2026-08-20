package com.ternbusty.takoyaki.spec;

import com.ternbusty.takoyaki.util.json.JsonMap;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * OCI runtime-spec bean. Field names match the spec verbatim; codecs are
 * hand-written {@code fromJson} / {@code toJson} pairs that walk a
 * {@link JsonMap} tree. No jackson, no reflection — eliminates ~3,000
 * reachable methods and ~4.6 MB of java.xml at native-image build time
 * vs jackson-databind.
 *
 * <p>Unknown JSON keys are silently ignored (mirrors jackson's
 * {@code FAIL_ON_UNKNOWN_PROPERTIES=false}). Null fields are dropped from
 * output (mirrors {@code Include.NON_NULL}).
 */
public final class Spec {
    public String ociVersion = "1.0.0";
    public Root root;
    public Process process;
    public String hostname;
    public String domainname;
    public Linux linux;
    public List<Mount> mounts;
    public Hooks hooks;
    public Map<String, String> annotations;

    public boolean hasNamespace(String type) {
        if (linux == null || linux.namespaces == null) return false;
        for (Namespace ns : linux.namespaces) {
            if (type.equals(ns.type)) return true;
        }
        return false;
    }

    /** True when the spec creates a NEW namespace of this type (no .path). */
    public boolean isCreatingNamespace(String type) {
        if (linux == null || linux.namespaces == null) return false;
        for (Namespace ns : linux.namespaces) {
            if (type.equals(ns.type) && (ns.path == null || ns.path.isEmpty())) return true;
        }
        return false;
    }

    public static Spec fromJson(Object node) {
        if (node == null) return null;
        Map<String, Object> o = JsonMap.asObject(node);
        Spec s = new Spec();
        String v = JsonMap.str(o, "ociVersion");
        if (v != null) s.ociVersion = v;
        s.root = Root.fromJson(o.get("root"));
        s.process = Process.fromJson(o.get("process"));
        s.hostname = JsonMap.str(o, "hostname");
        s.domainname = JsonMap.str(o, "domainname");
        s.linux = Linux.fromJson(o.get("linux"));
        s.mounts = JsonMap.list(o, "mounts", Mount::fromJson);
        s.hooks = Hooks.fromJson(o.get("hooks"));
        s.annotations = JsonMap.strMap(o, "annotations");
        return s;
    }

    public Object toJson() {
        Map<String, Object> o = JsonMap.obj();
        JsonMap.put(o, "ociVersion", ociVersion);
        if (root != null) JsonMap.put(o, "root", root.toJson());
        if (process != null) JsonMap.put(o, "process", process.toJson());
        JsonMap.put(o, "hostname", hostname);
        JsonMap.put(o, "domainname", domainname);
        if (linux != null) JsonMap.put(o, "linux", linux.toJson());
        JsonMap.put(o, "mounts", JsonMap.encList(mounts, Mount::toJson));
        if (hooks != null) JsonMap.put(o, "hooks", hooks.toJson());
        JsonMap.put(o, "annotations", annotations);
        return o;
    }

    public static final class Root {
        public String path;
        public boolean readonly;

        public static Root fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Root r = new Root();
            r.path = JsonMap.str(o, "path");
            r.readonly = JsonMap.boolOr(o, "readonly", false);
            return r;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "path", path);
            JsonMap.putAlways(o, "readonly", readonly);
            return o;
        }
    }

    public static final class Process {
        public List<String> args = Collections.emptyList();
        public List<String> env;
        public String cwd = "/";
        public Boolean noNewPrivileges;
        public User user = new User();
        public LinuxCapabilities capabilities;
        public List<POSIXRlimit> rlimits;
        public Long umask;
        public String apparmorProfile;
        public String selinuxLabel;
        public Boolean terminal;
        public Box consoleSize;
        public Integer oomScoreAdj;
        public IOPriority ioPriority;
        public Scheduler scheduler;
        public ExecCPUAffinity execCPUAffinity;

        public static Process fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Process p = new Process();
            List<String> a = JsonMap.strList(o, "args");
            if (a != null) p.args = a;
            p.env = JsonMap.strList(o, "env");
            String c = JsonMap.str(o, "cwd");
            if (c != null) p.cwd = c;
            p.noNewPrivileges = JsonMap.boolBoxed(o, "noNewPrivileges");
            User u = User.fromJson(o.get("user"));
            if (u != null) p.user = u;
            p.capabilities = LinuxCapabilities.fromJson(o.get("capabilities"));
            p.rlimits = JsonMap.list(o, "rlimits", POSIXRlimit::fromJson);
            p.umask = JsonMap.longBoxed(o, "umask");
            p.apparmorProfile = JsonMap.str(o, "apparmorProfile");
            p.selinuxLabel = JsonMap.str(o, "selinuxLabel");
            p.terminal = JsonMap.boolBoxed(o, "terminal");
            p.consoleSize = Box.fromJson(o.get("consoleSize"));
            p.oomScoreAdj = JsonMap.intBoxed(o, "oomScoreAdj");
            p.ioPriority = IOPriority.fromJson(o.get("ioPriority"));
            p.scheduler = Scheduler.fromJson(o.get("scheduler"));
            p.execCPUAffinity = ExecCPUAffinity.fromJson(o.get("execCPUAffinity"));
            return p;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "args", args);
            JsonMap.put(o, "env", env);
            JsonMap.put(o, "cwd", cwd);
            JsonMap.put(o, "noNewPrivileges", noNewPrivileges);
            if (user != null) JsonMap.put(o, "user", user.toJson());
            if (capabilities != null) JsonMap.put(o, "capabilities", capabilities.toJson());
            JsonMap.put(o, "rlimits", JsonMap.encList(rlimits, POSIXRlimit::toJson));
            JsonMap.put(o, "umask", umask);
            JsonMap.put(o, "apparmorProfile", apparmorProfile);
            JsonMap.put(o, "selinuxLabel", selinuxLabel);
            JsonMap.put(o, "terminal", terminal);
            if (consoleSize != null) JsonMap.put(o, "consoleSize", consoleSize.toJson());
            JsonMap.put(o, "oomScoreAdj", oomScoreAdj);
            if (ioPriority != null) JsonMap.put(o, "ioPriority", ioPriority.toJson());
            if (scheduler != null) JsonMap.put(o, "scheduler", scheduler.toJson());
            if (execCPUAffinity != null) JsonMap.put(o, "execCPUAffinity", execCPUAffinity.toJson());
            return o;
        }
    }

    public static final class IOPriority {
        public String clazz;
        public int priority;

        public static IOPriority fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            IOPriority p = new IOPriority();
            p.clazz = JsonMap.str(o, "class");
            p.priority = JsonMap.intOr(o, "priority", 0);
            return p;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "class", clazz);
            JsonMap.putAlways(o, "priority", priority);
            return o;
        }

        /** Map the OCI class string to the kernel constant. */
        public int classValue() {
            if (clazz == null) return 2; // IOPRIO_CLASS_BE
            return switch (clazz) {
                case "IOPRIO_CLASS_RT" -> 1;
                case "IOPRIO_CLASS_BE" -> 2;
                case "IOPRIO_CLASS_IDLE" -> 3;
                default -> 2;
            };
        }
    }

    public static final class Scheduler {
        public String policy;
        public Integer nice;
        public Integer priority;
        public List<String> flags;
        public Long runtime;
        public Long deadline;
        public Long period;

        public static Scheduler fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Scheduler s = new Scheduler();
            s.policy = JsonMap.str(o, "policy");
            s.nice = JsonMap.intBoxed(o, "nice");
            s.priority = JsonMap.intBoxed(o, "priority");
            s.flags = JsonMap.strList(o, "flags");
            s.runtime = JsonMap.longBoxed(o, "runtime");
            s.deadline = JsonMap.longBoxed(o, "deadline");
            s.period = JsonMap.longBoxed(o, "period");
            return s;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "policy", policy);
            JsonMap.put(o, "nice", nice);
            JsonMap.put(o, "priority", priority);
            JsonMap.put(o, "flags", flags);
            JsonMap.put(o, "runtime", runtime);
            JsonMap.put(o, "deadline", deadline);
            JsonMap.put(o, "period", period);
            return o;
        }

        /** Map the OCI policy string to the kernel constant. */
        public int policyValue() {
            if (policy == null) return 0; // SCHED_OTHER
            return switch (policy) {
                case "SCHED_OTHER" -> 0;
                case "SCHED_FIFO" -> 1;
                case "SCHED_RR" -> 2;
                case "SCHED_BATCH" -> 3;
                case "SCHED_ISO" -> 4;
                case "SCHED_IDLE" -> 5;
                case "SCHED_DEADLINE" -> 6;
                default -> 0;
            };
        }

        /** Combine flag strings into a bitmask. */
        public long flagBits() {
            if (flags == null) return 0;
            long bits = 0;
            for (String f : flags) {
                bits |= switch (f) {
                    case "SCHED_FLAG_RESET_ON_FORK" -> 0x01;
                    case "SCHED_FLAG_RECLAIM" -> 0x02;
                    case "SCHED_FLAG_DL_OVERRUN" -> 0x04;
                    case "SCHED_FLAG_KEEP_POLICY" -> 0x08;
                    case "SCHED_FLAG_KEEP_PARAMS" -> 0x10;
                    case "SCHED_FLAG_UTIL_CLAMP_MIN" -> 0x20;
                    case "SCHED_FLAG_UTIL_CLAMP_MAX" -> 0x40;
                    default -> 0L;
                };
            }
            return bits;
        }
    }

    public static final class ExecCPUAffinity {
        public String initial;
        public String fin;  // "final" is a Java keyword

        public static ExecCPUAffinity fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            ExecCPUAffinity a = new ExecCPUAffinity();
            a.initial = JsonMap.str(o, "initial");
            a.fin = JsonMap.str(o, "final");
            return a;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "initial", initial);
            JsonMap.put(o, "final", fin);
            return o;
        }

        /** Parse a Linux CPU list string (e.g. "0-3,5,7") into a bitmask. */
        public static long parseCpuList(String list) {
            if (list == null || list.isEmpty()) return 0;
            long mask = 0;
            for (String part : list.split(",")) {
                part = part.trim();
                int dash = part.indexOf('-');
                if (dash >= 0) {
                    int lo = Integer.parseInt(part.substring(0, dash).trim());
                    int hi = Integer.parseInt(part.substring(dash + 1).trim());
                    for (int i = lo; i <= hi && i < 64; i++) {
                        mask |= 1L << i;
                    }
                } else {
                    int cpu = Integer.parseInt(part);
                    if (cpu < 64) mask |= 1L << cpu;
                }
            }
            return mask;
        }
    }

    public static final class Box {
        public int height;
        public int width;

        public static Box fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Box b = new Box();
            b.height = JsonMap.intOr(o, "height", 0);
            b.width = JsonMap.intOr(o, "width", 0);
            return b;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "height", height);
            JsonMap.putAlways(o, "width", width);
            return o;
        }
    }

    public static final class Hook {
        public String path;
        public List<String> args;
        public List<String> env;
        public Long timeout;

        public static Hook fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Hook h = new Hook();
            h.path = JsonMap.str(o, "path");
            h.args = JsonMap.strList(o, "args");
            h.env = JsonMap.strList(o, "env");
            h.timeout = JsonMap.longBoxed(o, "timeout");
            return h;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "path", path);
            JsonMap.put(o, "args", args);
            JsonMap.put(o, "env", env);
            JsonMap.put(o, "timeout", timeout);
            return o;
        }
    }

    public static final class Hooks {
        public List<Hook> prestart;
        public List<Hook> createRuntime;
        public List<Hook> createContainer;
        public List<Hook> startContainer;
        public List<Hook> poststart;
        public List<Hook> poststop;

        public static Hooks fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Hooks h = new Hooks();
            h.prestart = JsonMap.list(o, "prestart", Hook::fromJson);
            h.createRuntime = JsonMap.list(o, "createRuntime", Hook::fromJson);
            h.createContainer = JsonMap.list(o, "createContainer", Hook::fromJson);
            h.startContainer = JsonMap.list(o, "startContainer", Hook::fromJson);
            h.poststart = JsonMap.list(o, "poststart", Hook::fromJson);
            h.poststop = JsonMap.list(o, "poststop", Hook::fromJson);
            return h;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "prestart", JsonMap.encList(prestart, Hook::toJson));
            JsonMap.put(o, "createRuntime", JsonMap.encList(createRuntime, Hook::toJson));
            JsonMap.put(o, "createContainer", JsonMap.encList(createContainer, Hook::toJson));
            JsonMap.put(o, "startContainer", JsonMap.encList(startContainer, Hook::toJson));
            JsonMap.put(o, "poststart", JsonMap.encList(poststart, Hook::toJson));
            JsonMap.put(o, "poststop", JsonMap.encList(poststop, Hook::toJson));
            return o;
        }
    }

    public static final class User {
        public int uid = 0;
        public int gid = 0;
        public List<Integer> additionalGids;
        public Long umask;

        public static User fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            User u = new User();
            u.uid = JsonMap.intOr(o, "uid", 0);
            u.gid = JsonMap.intOr(o, "gid", 0);
            u.additionalGids = JsonMap.intList(o, "additionalGids");
            u.umask = JsonMap.longBoxed(o, "umask");
            return u;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "uid", uid);
            JsonMap.putAlways(o, "gid", gid);
            JsonMap.put(o, "additionalGids", additionalGids);
            JsonMap.put(o, "umask", umask);
            return o;
        }
    }

    public static final class POSIXRlimit {
        public String type;
        public long hard;
        public long soft;

        public static POSIXRlimit fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            POSIXRlimit r = new POSIXRlimit();
            r.type = JsonMap.str(o, "type");
            r.hard = JsonMap.longOr(o, "hard", 0);
            r.soft = JsonMap.longOr(o, "soft", 0);
            return r;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "type", type);
            JsonMap.putAlways(o, "hard", hard);
            JsonMap.putAlways(o, "soft", soft);
            return o;
        }
    }

    public static final class LinuxCapabilities {
        public List<String> bounding;
        public List<String> effective;
        public List<String> inheritable;
        public List<String> permitted;
        public List<String> ambient;

        public static LinuxCapabilities fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxCapabilities c = new LinuxCapabilities();
            c.bounding = JsonMap.strList(o, "bounding");
            c.effective = JsonMap.strList(o, "effective");
            c.inheritable = JsonMap.strList(o, "inheritable");
            c.permitted = JsonMap.strList(o, "permitted");
            c.ambient = JsonMap.strList(o, "ambient");
            return c;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "bounding", bounding);
            JsonMap.put(o, "effective", effective);
            JsonMap.put(o, "inheritable", inheritable);
            JsonMap.put(o, "permitted", permitted);
            JsonMap.put(o, "ambient", ambient);
            return o;
        }
    }

    public static final class Namespace {
        public String type;
        public String path;

        public static Namespace fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Namespace n = new Namespace();
            n.type = JsonMap.str(o, "type");
            n.path = JsonMap.str(o, "path");
            return n;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "type", type);
            JsonMap.put(o, "path", path);
            return o;
        }
    }

    public static final class IdMapping {
        public long containerID;
        public long hostID;
        public long size;

        public static IdMapping fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            IdMapping m = new IdMapping();
            m.containerID = JsonMap.longOr(o, "containerID", 0);
            m.hostID = JsonMap.longOr(o, "hostID", 0);
            m.size = JsonMap.longOr(o, "size", 0);
            return m;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "containerID", containerID);
            JsonMap.putAlways(o, "hostID", hostID);
            JsonMap.putAlways(o, "size", size);
            return o;
        }
    }

    public static final class Mount {
        public String destination;
        public String source;
        public String type;
        public List<String> options;
        public List<IdMapping> uidMappings;
        public List<IdMapping> gidMappings;

        public static Mount fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Mount m = new Mount();
            m.destination = JsonMap.str(o, "destination");
            m.source = JsonMap.str(o, "source");
            m.type = JsonMap.str(o, "type");
            m.options = JsonMap.strList(o, "options");
            m.uidMappings = JsonMap.list(o, "uidMappings", IdMapping::fromJson);
            m.gidMappings = JsonMap.list(o, "gidMappings", IdMapping::fromJson);
            return m;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "destination", destination);
            JsonMap.put(o, "source", source);
            JsonMap.put(o, "type", type);
            JsonMap.put(o, "options", options);
            JsonMap.put(o, "uidMappings", JsonMap.encList(uidMappings, IdMapping::toJson));
            JsonMap.put(o, "gidMappings", JsonMap.encList(gidMappings, IdMapping::toJson));
            return o;
        }
    }

    public static final class LinuxResources {
        public LinuxMemory memory;
        public LinuxCpu cpu;
        public LinuxPids pids;
        public List<LinuxDeviceCgroup> devices;
        public List<LinuxHugepageLimit> hugepageLimits;
        public LinuxBlockIO blockIO;
        /**
         * Free-form cgroup v2 pass-through map. Each key is a control-file name
         * relative to the cgroup directory (e.g. {@code "io.weight"} or
         * {@code "hugetlb.2MB.max"}), each value is written verbatim. Lets
         * spec authors reach controllers that aren't modelled by the strongly
         * typed fields above without waiting for takoyaki to grow them.
         */
        public Map<String, String> unified;

        public static LinuxResources fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxResources r = new LinuxResources();
            r.memory = LinuxMemory.fromJson(o.get("memory"));
            r.cpu = LinuxCpu.fromJson(o.get("cpu"));
            r.pids = LinuxPids.fromJson(o.get("pids"));
            r.devices = JsonMap.list(o, "devices", LinuxDeviceCgroup::fromJson);
            r.hugepageLimits = JsonMap.list(o, "hugepageLimits", LinuxHugepageLimit::fromJson);
            r.blockIO = LinuxBlockIO.fromJson(o.get("blockIO"));
            r.unified = JsonMap.strMap(o, "unified");
            return r;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            if (memory != null) JsonMap.put(o, "memory", memory.toJson());
            if (cpu != null) JsonMap.put(o, "cpu", cpu.toJson());
            if (pids != null) JsonMap.put(o, "pids", pids.toJson());
            JsonMap.put(o, "devices", JsonMap.encList(devices, LinuxDeviceCgroup::toJson));
            JsonMap.put(o, "hugepageLimits",
                    JsonMap.encList(hugepageLimits, LinuxHugepageLimit::toJson));
            if (blockIO != null) JsonMap.put(o, "blockIO", blockIO.toJson());
            if (unified != null && !unified.isEmpty()) JsonMap.put(o, "unified", unified);
            return o;
        }
    }

    public static final class LinuxHugepageLimit {
        /** e.g. "2MB", "1GB". Matches cgroup v2's hugetlb.&lt;size&gt;.max naming. */
        public String pageSize;
        public Long limit;

        public static LinuxHugepageLimit fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxHugepageLimit h = new LinuxHugepageLimit();
            h.pageSize = JsonMap.str(o, "pageSize");
            h.limit = JsonMap.longBoxed(o, "limit");
            return h;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "pageSize", pageSize);
            JsonMap.put(o, "limit", limit);
            return o;
        }
    }

    public static final class LinuxBlockIO {
        /** Default weight, 10..1000. Maps to cgroup v2 io.weight. */
        public Long weight;
        public List<LinuxThrottleDevice> throttleReadBpsDevice;
        public List<LinuxThrottleDevice> throttleWriteBpsDevice;
        public List<LinuxThrottleDevice> throttleReadIOPSDevice;
        public List<LinuxThrottleDevice> throttleWriteIOPSDevice;

        public static LinuxBlockIO fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxBlockIO b = new LinuxBlockIO();
            b.weight = JsonMap.longBoxed(o, "weight");
            b.throttleReadBpsDevice = JsonMap.list(o,
                    "throttleReadBpsDevice", LinuxThrottleDevice::fromJson);
            b.throttleWriteBpsDevice = JsonMap.list(o,
                    "throttleWriteBpsDevice", LinuxThrottleDevice::fromJson);
            b.throttleReadIOPSDevice = JsonMap.list(o,
                    "throttleReadIOPSDevice", LinuxThrottleDevice::fromJson);
            b.throttleWriteIOPSDevice = JsonMap.list(o,
                    "throttleWriteIOPSDevice", LinuxThrottleDevice::fromJson);
            return b;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "weight", weight);
            JsonMap.put(o, "throttleReadBpsDevice",
                    JsonMap.encList(throttleReadBpsDevice, LinuxThrottleDevice::toJson));
            JsonMap.put(o, "throttleWriteBpsDevice",
                    JsonMap.encList(throttleWriteBpsDevice, LinuxThrottleDevice::toJson));
            JsonMap.put(o, "throttleReadIOPSDevice",
                    JsonMap.encList(throttleReadIOPSDevice, LinuxThrottleDevice::toJson));
            JsonMap.put(o, "throttleWriteIOPSDevice",
                    JsonMap.encList(throttleWriteIOPSDevice, LinuxThrottleDevice::toJson));
            return o;
        }
    }

    public static final class LinuxThrottleDevice {
        public Long major;
        public Long minor;
        /** bytes/sec for *BpsDevice, IOPS for *IOPSDevice. */
        public Long rate;

        public static LinuxThrottleDevice fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxThrottleDevice d = new LinuxThrottleDevice();
            d.major = JsonMap.longBoxed(o, "major");
            d.minor = JsonMap.longBoxed(o, "minor");
            d.rate = JsonMap.longBoxed(o, "rate");
            return d;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "major", major);
            JsonMap.put(o, "minor", minor);
            JsonMap.put(o, "rate", rate);
            return o;
        }
    }

    public static final class LinuxMemory {
        public Long limit;
        public Long reservation;
        public Long swap;
        public Boolean checkBeforeUpdate;

        public static LinuxMemory fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxMemory m = new LinuxMemory();
            m.limit = JsonMap.longBoxed(o, "limit");
            m.reservation = JsonMap.longBoxed(o, "reservation");
            m.swap = JsonMap.longBoxed(o, "swap");
            m.checkBeforeUpdate = JsonMap.boolBoxed(o, "checkBeforeUpdate");
            return m;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "limit", limit);
            JsonMap.put(o, "reservation", reservation);
            JsonMap.put(o, "swap", swap);
            JsonMap.put(o, "checkBeforeUpdate", checkBeforeUpdate);
            return o;
        }
    }

    public static final class LinuxCpu {
        public Long shares;
        public Long quota;
        public Long period;
        public String cpus;
        public String mems;
        public Long realtimePeriod;
        public Long realtimeRuntime;
        /** Linux 5.14+ CPU burst window in the same units as quota. */
        public Long burst;
        /** 1 → SCHED_IDLE cgroup (best-effort scheduling). Linux 5.15+. */
        public Long idle;

        public static LinuxCpu fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxCpu c = new LinuxCpu();
            c.shares = JsonMap.longBoxed(o, "shares");
            c.quota = JsonMap.longBoxed(o, "quota");
            c.period = JsonMap.longBoxed(o, "period");
            c.cpus = JsonMap.str(o, "cpus");
            c.mems = JsonMap.str(o, "mems");
            c.realtimePeriod = JsonMap.longBoxed(o, "realtimePeriod");
            c.realtimeRuntime = JsonMap.longBoxed(o, "realtimeRuntime");
            c.burst = JsonMap.longBoxed(o, "burst");
            c.idle = JsonMap.longBoxed(o, "idle");
            return c;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "shares", shares);
            JsonMap.put(o, "quota", quota);
            JsonMap.put(o, "period", period);
            JsonMap.put(o, "cpus", cpus);
            JsonMap.put(o, "mems", mems);
            JsonMap.put(o, "realtimePeriod", realtimePeriod);
            JsonMap.put(o, "realtimeRuntime", realtimeRuntime);
            JsonMap.put(o, "burst", burst);
            JsonMap.put(o, "idle", idle);
            return o;
        }
    }

    public static final class LinuxPids {
        public long limit;

        public static LinuxPids fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxPids p = new LinuxPids();
            p.limit = JsonMap.longOr(o, "limit", 0);
            return p;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "limit", limit);
            return o;
        }
    }

    public static final class SeccompArg {
        public int index;
        public long value;
        public Long valueTwo;
        public String op;

        public static SeccompArg fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            SeccompArg a = new SeccompArg();
            a.index = JsonMap.intOr(o, "index", 0);
            a.value = JsonMap.longOr(o, "value", 0);
            a.valueTwo = JsonMap.longBoxed(o, "valueTwo");
            a.op = JsonMap.str(o, "op");
            return a;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "index", index);
            JsonMap.putAlways(o, "value", value);
            JsonMap.put(o, "valueTwo", valueTwo);
            JsonMap.put(o, "op", op);
            return o;
        }
    }

    public static final class LinuxSyscall {
        public List<String> names;
        public String action;
        public Long errnoRet;
        public List<SeccompArg> args;

        public static LinuxSyscall fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxSyscall s = new LinuxSyscall();
            s.names = JsonMap.strList(o, "names");
            s.action = JsonMap.str(o, "action");
            s.errnoRet = JsonMap.longBoxed(o, "errnoRet");
            s.args = JsonMap.list(o, "args", SeccompArg::fromJson);
            return s;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "names", names);
            JsonMap.put(o, "action", action);
            JsonMap.put(o, "errnoRet", errnoRet);
            JsonMap.put(o, "args", JsonMap.encList(args, SeccompArg::toJson));
            return o;
        }
    }

    public static final class LinuxSeccomp {
        public String defaultAction;
        public Long defaultErrnoRet;
        public List<String> architectures;
        public List<LinuxSyscall> syscalls;
        public List<String> flags;
        public String listenerPath;
        public String listenerMetadata;

        public static LinuxSeccomp fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxSeccomp s = new LinuxSeccomp();
            s.defaultAction = JsonMap.str(o, "defaultAction");
            s.defaultErrnoRet = JsonMap.longBoxed(o, "defaultErrnoRet");
            s.architectures = JsonMap.strList(o, "architectures");
            s.syscalls = JsonMap.list(o, "syscalls", LinuxSyscall::fromJson);
            s.flags = JsonMap.strList(o, "flags");
            s.listenerPath = JsonMap.str(o, "listenerPath");
            s.listenerMetadata = JsonMap.str(o, "listenerMetadata");
            return s;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "defaultAction", defaultAction);
            JsonMap.put(o, "defaultErrnoRet", defaultErrnoRet);
            JsonMap.put(o, "architectures", architectures);
            JsonMap.put(o, "syscalls", JsonMap.encList(syscalls, LinuxSyscall::toJson));
            JsonMap.put(o, "flags", flags);
            JsonMap.put(o, "listenerPath", listenerPath);
            JsonMap.put(o, "listenerMetadata", listenerMetadata);
            return o;
        }
    }

    public static final class LinuxDevice {
        public String path;
        public String type;
        public Long major;
        public Long minor;
        public Long fileMode;
        public Long uid;
        public Long gid;

        public static LinuxDevice fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxDevice d = new LinuxDevice();
            d.path = JsonMap.str(o, "path");
            d.type = JsonMap.str(o, "type");
            d.major = JsonMap.longBoxed(o, "major");
            d.minor = JsonMap.longBoxed(o, "minor");
            d.fileMode = JsonMap.longBoxed(o, "fileMode");
            d.uid = JsonMap.longBoxed(o, "uid");
            d.gid = JsonMap.longBoxed(o, "gid");
            return d;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "path", path);
            JsonMap.put(o, "type", type);
            JsonMap.put(o, "major", major);
            JsonMap.put(o, "minor", minor);
            JsonMap.put(o, "fileMode", fileMode);
            JsonMap.put(o, "uid", uid);
            JsonMap.put(o, "gid", gid);
            return o;
        }
    }

    public static final class LinuxDeviceCgroup {
        public boolean allow;
        public String type;
        public Long major;
        public Long minor;
        public String access;

        public static LinuxDeviceCgroup fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            LinuxDeviceCgroup d = new LinuxDeviceCgroup();
            d.allow = JsonMap.boolOr(o, "allow", false);
            d.type = JsonMap.str(o, "type");
            d.major = JsonMap.longBoxed(o, "major");
            d.minor = JsonMap.longBoxed(o, "minor");
            d.access = JsonMap.str(o, "access");
            return d;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "allow", allow);
            JsonMap.put(o, "type", type);
            JsonMap.put(o, "major", major);
            JsonMap.put(o, "minor", minor);
            JsonMap.put(o, "access", access);
            return o;
        }
    }

    public static final class TimeOffset {
        public long secs;
        public long nanosecs;

        public static TimeOffset fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            TimeOffset t = new TimeOffset();
            t.secs = JsonMap.longOr(o, "secs", 0);
            t.nanosecs = JsonMap.longOr(o, "nanosecs", 0);
            return t;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.putAlways(o, "secs", secs);
            JsonMap.putAlways(o, "nanosecs", nanosecs);
            return o;
        }
    }

    public static final class Linux {
        public List<Namespace> namespaces;
        public List<IdMapping> uidMappings;
        public List<IdMapping> gidMappings;
        public LinuxResources resources;
        public String cgroupsPath;
        public LinuxSeccomp seccomp;
        public List<LinuxDevice> devices;
        public List<String> maskedPaths;
        public List<String> readonlyPaths;
        public String rootfsPropagation;
        public Map<String, String> sysctl;
        public Map<String, TimeOffset> timeOffsets;
        public MemoryPolicy memoryPolicy;
        public Map<String, NetDevice> netDevices;

        public static Linux fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            Linux l = new Linux();
            l.namespaces = JsonMap.list(o, "namespaces", Namespace::fromJson);
            l.uidMappings = JsonMap.list(o, "uidMappings", IdMapping::fromJson);
            l.gidMappings = JsonMap.list(o, "gidMappings", IdMapping::fromJson);
            l.resources = LinuxResources.fromJson(o.get("resources"));
            l.cgroupsPath = JsonMap.str(o, "cgroupsPath");
            l.seccomp = LinuxSeccomp.fromJson(o.get("seccomp"));
            l.devices = JsonMap.list(o, "devices", LinuxDevice::fromJson);
            l.maskedPaths = JsonMap.strList(o, "maskedPaths");
            l.readonlyPaths = JsonMap.strList(o, "readonlyPaths");
            l.rootfsPropagation = JsonMap.str(o, "rootfsPropagation");
            l.sysctl = JsonMap.strMap(o, "sysctl");
            l.timeOffsets = JsonMap.map(o, "timeOffsets", TimeOffset::fromJson);
            l.memoryPolicy = MemoryPolicy.fromJson(o.get("memoryPolicy"));
            l.netDevices = JsonMap.map(o, "netDevices", NetDevice::fromJson);
            return l;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "namespaces", JsonMap.encList(namespaces, Namespace::toJson));
            JsonMap.put(o, "uidMappings", JsonMap.encList(uidMappings, IdMapping::toJson));
            JsonMap.put(o, "gidMappings", JsonMap.encList(gidMappings, IdMapping::toJson));
            if (resources != null) JsonMap.put(o, "resources", resources.toJson());
            JsonMap.put(o, "cgroupsPath", cgroupsPath);
            if (seccomp != null) JsonMap.put(o, "seccomp", seccomp.toJson());
            JsonMap.put(o, "devices", JsonMap.encList(devices, LinuxDevice::toJson));
            JsonMap.put(o, "maskedPaths", maskedPaths);
            JsonMap.put(o, "readonlyPaths", readonlyPaths);
            JsonMap.put(o, "rootfsPropagation", rootfsPropagation);
            JsonMap.put(o, "sysctl", sysctl);
            if (memoryPolicy != null) JsonMap.put(o, "memoryPolicy", memoryPolicy.toJson());
            if (netDevices != null) {
                Map<String, Object> nd = JsonMap.obj();
                for (Map.Entry<String, NetDevice> e : netDevices.entrySet()) {
                    nd.put(e.getKey(), e.getValue().toJson());
                }
                JsonMap.put(o, "netDevices", nd);
            }
            if (timeOffsets != null) {
                Map<String, Object> to = JsonMap.obj();
                for (Map.Entry<String, TimeOffset> e : timeOffsets.entrySet()) {
                    to.put(e.getKey(), e.getValue().toJson());
                }
                JsonMap.put(o, "timeOffsets", to);
            }
            return o;
        }
    }

    /** NUMA memory policy (linux.memoryPolicy). */
    public static final class MemoryPolicy {
        public String mode;
        public String nodes;
        public List<String> flags;

        public static MemoryPolicy fromJson(Object node) {
            if (node == null) return null;
            Map<String, Object> o = JsonMap.asObject(node);
            MemoryPolicy m = new MemoryPolicy();
            m.mode = JsonMap.str(o, "mode");
            m.nodes = JsonMap.str(o, "nodes");
            m.flags = JsonMap.strList(o, "flags");
            return m;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "mode", mode);
            JsonMap.put(o, "nodes", nodes);
            JsonMap.put(o, "flags", flags);
            return o;
        }
    }

    /** Network device to move into the container namespace (linux.netDevices). */
    public static final class NetDevice {
        public String name;

        public static NetDevice fromJson(Object node) {
            if (node == null) return new NetDevice();
            Map<String, Object> o = JsonMap.asObject(node);
            NetDevice d = new NetDevice();
            d.name = JsonMap.str(o, "name");
            return d;
        }

        public Object toJson() {
            Map<String, Object> o = JsonMap.obj();
            JsonMap.put(o, "name", name);
            return o;
        }
    }
}
