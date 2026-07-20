# Changelog

## [0.3.0](https://github.com/ternbusty/takoyaki/compare/v0.2.0...v0.3.0) (2026-07-20)


### 🎉 Features

* **cgroup:** honour cpu.burst / cpu.idle, hugepageLimits and blockIO ([#39](https://github.com/ternbusty/takoyaki/issues/39)) ([2f6f8d1](https://github.com/ternbusty/takoyaki/commit/2f6f8d115f1544e8a7cdf0d10e3d8b3b149988d9))
* **seccomp:** translate filter flags, reject NOTIFY-on-write, validate errno ([#36](https://github.com/ternbusty/takoyaki/issues/36)) ([195ded2](https://github.com/ternbusty/takoyaki/commit/195ded236a593b1ef6076ed1cf183eaa5f4dfc28))


### 🐛 Bug Fixes

* **capability:** warn on unknown cap names, pre-check ambient raise ([#37](https://github.com/ternbusty/takoyaki/issues/37)) ([02f8a22](https://github.com/ternbusty/takoyaki/commit/02f8a22c09bf53e05ac3eeaad3aec9dec8a41348))
* **exec:** apply the container's process restrictions instead of bare setns ([#46](https://github.com/ternbusty/takoyaki/issues/46)) ([70edfc4](https://github.com/ternbusty/takoyaki/commit/70edfc44fa6302c208f5d4459a5fd1206bb86247))
* **rootfs:** add /dev/console to the default bind-mount set ([#40](https://github.com/ternbusty/takoyaki/issues/40)) ([10d159f](https://github.com/ternbusty/takoyaki/commit/10d159fa784ea5234565848c80f99125f928275b))


### ⚡ Performance Improvements

* **seccomp:** switch to binary-tree matching once the rule set exceeds 32 ([#38](https://github.com/ternbusty/takoyaki/issues/38)) ([273dbb6](https://github.com/ternbusty/takoyaki/commit/273dbb6240cc8fa47679baef99de31967e1b17a2))


### 🔗 Dependencies

* **deps:** bump org.graalvm.buildtools.native from 1.1.3 to 1.1.4 ([#43](https://github.com/ternbusty/takoyaki/issues/43)) ([e4ef69b](https://github.com/ternbusty/takoyaki/commit/e4ef69bd70245bd5c0afaf84cde0dc90175e915c))
* **deps:** bump org.graalvm.sdk:nativeimage from 25.0.3 to 25.1.3 ([#41](https://github.com/ternbusty/takoyaki/issues/41)) ([2165bb3](https://github.com/ternbusty/takoyaki/commit/2165bb3872ae0ed7a355aa78475f0c941328e115))
* **deps:** bump org.junit:junit-bom from 6.1.1 to 6.1.2 ([#44](https://github.com/ternbusty/takoyaki/issues/44)) ([7c050d6](https://github.com/ternbusty/takoyaki/commit/7c050d6219f34af9ce34d6026e7bbf669f249465))

## [0.2.0](https://github.com/ternbusty/takoyaki/compare/v0.1.1...v0.2.0) (2026-07-05)


### 🎉 Features

* **cgroup:** parse and apply resources.unified, warn on realtime CPU ([#35](https://github.com/ternbusty/takoyaki/issues/35)) ([6713d0b](https://github.com/ternbusty/takoyaki/commit/6713d0bd699e164bac53bd4699a4dcd90d228de1))
* **seccomp:** load conditionally on NNP to align with runc / youki ([#28](https://github.com/ternbusty/takoyaki/issues/28)) ([ee8d859](https://github.com/ternbusty/takoyaki/commit/ee8d859efdfdedc631aef134147c47092d9404fd))


### 🐛 Bug Fixes

* **hooks:** always clear env before running a hook ([#34](https://github.com/ternbusty/takoyaki/issues/34)) ([bf9545b](https://github.com/ternbusty/takoyaki/commit/bf9545b62ddc839705576fd809791783be30ea0e))
* **hooks:** run createContainer and startContainer inside the init ([#31](https://github.com/ternbusty/takoyaki/issues/31)) ([8f9a172](https://github.com/ternbusty/takoyaki/commit/8f9a1720391ee6f19b19488a433d7cda5e477566))
* **seccomp:** abort init when seccomp_load fails instead of silently continuing ([#33](https://github.com/ternbusty/takoyaki/issues/33)) ([bedf686](https://github.com/ternbusty/takoyaki/commit/bedf686c07d3ce590bafb74e4172379f3513832c))
* **sysctl:** reject non-namespaced keys before writing ([#27](https://github.com/ternbusty/takoyaki/issues/27)) ([12ab645](https://github.com/ternbusty/takoyaki/commit/12ab64507e3b0a8894325794583211d01861e05a))
* **usermap:** only write setgroups=deny when writing gid_map directly ([#32](https://github.com/ternbusty/takoyaki/issues/32)) ([ebc2aef](https://github.com/ternbusty/takoyaki/commit/ebc2aef4e71186aa3dcf9b40d15c4aa3731f2f7b))


### ⚡ Performance Improvements

* add run subcommand that does create + start + wait + delete in one process ([#18](https://github.com/ternbusty/takoyaki/issues/18)) ([26e9638](https://github.com/ternbusty/takoyaki/commit/26e963894365153b624bcaee6c64ef81d78753f6))
* cold start optimizations (-12 ms TOTAL, -34% --version) ([6842e0f](https://github.com/ternbusty/takoyaki/commit/6842e0fdba6246d11bf842dfc0739a1f3c4c647d))
* replace jackson-databind with a hand-rolled JSON codec ([#16](https://github.com/ternbusty/takoyaki/issues/16)) ([483f25a](https://github.com/ternbusty/takoyaki/commit/483f25aae1e13c0ab0c176036fd1c52ae27cd847))
* trim glibc locale init and drop picocli ([#15](https://github.com/ternbusty/takoyaki/issues/15)) ([faa0af3](https://github.com/ternbusty/takoyaki/commit/faa0af36d7e3238607075337327c3375ac10612a))


### 🔗 Dependencies

* **deps:** bump gradle-wrapper from 9.5.1 to 9.6.1 ([#25](https://github.com/ternbusty/takoyaki/issues/25)) ([35509c3](https://github.com/ternbusty/takoyaki/commit/35509c3e913a711c47f0c03114fcd41c6fa00642))
* **deps:** bump org.graalvm.buildtools.native from 0.11.1 to 1.1.2 ([#19](https://github.com/ternbusty/takoyaki/issues/19)) ([f517429](https://github.com/ternbusty/takoyaki/commit/f5174296e310022613ecbab24fc97d59a03b6b34))
* **deps:** bump org.graalvm.buildtools.native from 1.1.2 to 1.1.3 ([#24](https://github.com/ternbusty/takoyaki/issues/24)) ([ceb67cd](https://github.com/ternbusty/takoyaki/commit/ceb67cd5de089812533bf20b12df8f76103df8c3))
* **deps:** bump org.graalvm.sdk:nativeimage from 25.0.2 to 25.0.3 ([#20](https://github.com/ternbusty/takoyaki/issues/20)) ([7b8e7bf](https://github.com/ternbusty/takoyaki/commit/7b8e7bf1f45e3f383a5e1978f90808a3cf0d1123))
* **deps:** bump org.junit:junit-bom from 6.1.0 to 6.1.1 ([#23](https://github.com/ternbusty/takoyaki/issues/23)) ([7f48e78](https://github.com/ternbusty/takoyaki/commit/7f48e78bb776de1c1297c76607f74afeccb41716))

## [0.1.1](https://github.com/ternbusty/takoyaki/compare/v0.1.0...v0.1.1) (2026-06-11)


### 🎉 Features

* **hooks,kill:** make prestart hook failure abort create; parse kill signal first ([777afc8](https://github.com/ternbusty/takoyaki/commit/777afc817508c80bb2f7b33b5b1e96354b91320a))


### 🐛 Bug Fixes

* **build:** import java.time.Duration in build.gradle.kts ([f3612d5](https://github.com/ternbusty/takoyaki/commit/f3612d53760282ef101726602760dc22bbb5c2ac))
* **cgroup:** retry rmdir until it succeeds; CI was still racing teardown ([0da7bcf](https://github.com/ternbusty/takoyaki/commit/0da7bcfcd0f01f6d3144111892900b8cae2eee61))
* **cgroup:** use cgroup.kill + procs poll to avoid rmdir EBUSY race ([a11d2cc](https://github.com/ternbusty/takoyaki/commit/a11d2cced9108d9fa811f82f4432e4be239e65da))
* **create,start:** move process.args validation from create to start ([54e1f96](https://github.com/ternbusty/takoyaki/commit/54e1f9673937bf0941b83e4265eefa1897434b36))
* **start:** revert process.args validation; runtime-tools wants no error ([2bb9ae2](https://github.com/ternbusty/takoyaki/commit/2bb9ae2376d84560391a193d7923d3ed58f2d0f3))


### 🔗 Dependencies

* **deps:** bump com.fasterxml.jackson.datatype:jackson-datatype-jdk8 ([#10](https://github.com/ternbusty/takoyaki/issues/10)) ([9033ed2](https://github.com/ternbusty/takoyaki/commit/9033ed2436eb7700530e775d5bb325c63e24d933))
* **deps:** bump jackson-databind from 2.19.0 to 2.22.0 ([bdb2e02](https://github.com/ternbusty/takoyaki/commit/bdb2e02d42c76f9a672e977f7a61aefe4d96f41b))
* **deps:** bump org.junit:junit-bom from 5.11.4 to 6.1.0 ([#9](https://github.com/ternbusty/takoyaki/issues/9)) ([2e972ef](https://github.com/ternbusty/takoyaki/commit/2e972ef7d74218dc15935b2e53ac3442455768e1))
* **deps:** bump org.mockito:mockito-core from 5.20.0 to 5.23.0 ([#7](https://github.com/ternbusty/takoyaki/issues/7)) ([bb0d607](https://github.com/ternbusty/takoyaki/commit/bb0d607edcb1c192624a9bc31f50c5a8af23b1d4))
* **deps:** bump org.mockito:mockito-junit-jupiter from 5.20.0 to 5.23.0 ([#8](https://github.com/ternbusty/takoyaki/issues/8)) ([8f4af60](https://github.com/ternbusty/takoyaki/commit/8f4af60afecb8a936817600904cddef49d1e1848))

## 0.1.0 (2026-06-10)


### 🎉 Features

* add bootstrap C constructor for two-stage namespace setup ([87bbd33](https://github.com/ternbusty/takoyaki/commit/87bbd33015ae68bec66ef9ca2996136f64161042))
* add capability, rlimit, setgroups, and close_range support ([c34d59d](https://github.com/ternbusty/takoyaki/commit/c34d59dbe855d43c6ded83b4fbc0a1a971ee9c04))
* add main and init process orchestration ([ae5c977](https://github.com/ternbusty/takoyaki/commit/ae5c9773d071aea656b908bed8611fceb0337589))
* add oci spec, container state, and runtime config ([7e465c3](https://github.com/ternbusty/takoyaki/commit/7e465c329f99df3da4b3c2778be2bfae9b40120b))
* add panama ffm wrappers for libc and bootstrap symbol ([5925cef](https://github.com/ternbusty/takoyaki/commit/5925cef225007974e72068ddb41a5b808716543f))
* add rootfs pivot, cgroup v2 setup, and namespace flag mapping ([63569d7](https://github.com/ternbusty/takoyaki/commit/63569d707b0025f548dbf2d03a6dc7092642d0c7))
* add runc-compatible cli with create/start/state/kill/delete ([6ab1ebc](https://github.com/ternbusty/takoyaki/commit/6ab1ebc854b20c22aa211ec5eca701f0bbb1a6c8))
* add seccomp filter via libseccomp ffm bindings ([18b11fb](https://github.com/ternbusty/takoyaki/commit/18b11fbba7512b1c175427c23ddca9b4eb6e7518))
* add structured logger and jackson json codec ([0a5f3f5](https://github.com/ternbusty/takoyaki/commit/0a5f3f52316696b58a598b7c2a5a8ba19006e9df))
* add unix socket notify and sync channel ipc ([527199c](https://github.com/ternbusty/takoyaki/commit/527199ccf316cda0fb6e77041b39a4b66eabb17b))
* **apparmor:** add profile staging via /proc/self/attr/exec ([327d992](https://github.com/ternbusty/takoyaki/commit/327d9921ebe7545dd4972b5403df2a39b471858b))
* **bootstrap:** use clone3 with pidfd, fall back to clone ([debc84a](https://github.com/ternbusty/takoyaki/commit/debc84af38c1fa5004623fd744230df46c12ab5f))
* **cgroup:** add applyLimitsOnly entry point for update command ([8f3bf2f](https://github.com/ternbusty/takoyaki/commit/8f3bf2f97bbef8fa7cfb5904f95ab989beccf50c))
* **cgroup:** emit bpf program for linux.resources.devices and attach ([dd4e17e](https://github.com/ternbusty/takoyaki/commit/dd4e17ec4ac7d309ad4afc63c0c2e73147e9e11b))
* **cgroup:** write cpuset.cpus and cpuset.mems for cpu controller ([db1dd3f](https://github.com/ternbusty/takoyaki/commit/db1dd3f40145e8ee9aad3b73dbb99b39b56a7c01))
* **cli:** add events subcommand for resource stats stream ([c4655fa](https://github.com/ternbusty/takoyaki/commit/c4655fa9c29a3de0b736cb74f0b101edfdc026b0))
* **cli:** add exec subcommand via setns to join existing namespaces ([a9c81c0](https://github.com/ternbusty/takoyaki/commit/a9c81c0213a79b6fae1ce6aace8be87c6da9f9c3))
* **cli:** add list and ps subcommands ([a248ff6](https://github.com/ternbusty/takoyaki/commit/a248ff6de8bc42494a49bde8b9e8af070e6519fd))
* **cli:** add pause and resume via cgroup.freeze ([2a64834](https://github.com/ternbusty/takoyaki/commit/2a6483417d2cd7737b687e8b732a2f54674ea68e))
* **cli:** add update subcommand for runtime resource changes ([714647f](https://github.com/ternbusty/takoyaki/commit/714647f12e477a717d68925b16a4fb74841f6e88))
* **cli:** register new subcommands on TakoyakiRoot ([0d8e8d5](https://github.com/ternbusty/takoyaki/commit/0d8e8d55f6b8f5fd724fa96532eb56c6d15ef8ed))
* **console:** allocate pty and ship master fd via console-socket ([c76fdda](https://github.com/ternbusty/takoyaki/commit/c76fdda259effb4f3462dd4d28f57ee3603990c8))
* **hooks:** add lifecycle hook runner with stdin state pipe ([ea79a23](https://github.com/ternbusty/takoyaki/commit/ea79a239ccb8d8c23f817b4b5edf5a2f4d7e8688))
* **hooks:** integrate lifecycle hooks in main/start/delete ([a09cb8f](https://github.com/ternbusty/takoyaki/commit/a09cb8f95257c7eaf5eb241d775987687fe9bcd3))
* **init:** wire new hardening modules and switch to setres*/non-dumpable ([35d8246](https://github.com/ternbusty/takoyaki/commit/35d8246cd172ae251f9bbcafe8707ebbb483951a))
* **init:** wire selinux, keyring, timens offsets, and reflect-config additions ([2102152](https://github.com/ternbusty/takoyaki/commit/21021528f29c843e13b72ad15dd295bd484fd5d7))
* **ipc:** add SCM_RIGHTS sendmsg/recvmsg helper for fd passing ([ac31034](https://github.com/ternbusty/takoyaki/commit/ac3103426ae52eee12a8b406188dd886098dcdee))
* link libseccomp at NEEDED to drop explicit preload ([907e35e](https://github.com/ternbusty/takoyaki/commit/907e35e9b197fb1fbc6070a3e64dc914e8452d31))
* **namespace:** unshare cgroup and time namespaces in bootstrap ([868b29c](https://github.com/ternbusty/takoyaki/commit/868b29ca0575d3925e877145e4a4db58386b37d1))
* **network:** add loopback interface up via ioctl ([c7e6080](https://github.com/ternbusty/takoyaki/commit/c7e6080925f6e94ccff94b5982ae56bca04da60a))
* **oci:** pass more of opencontainers/runtime-tools validation suite ([d9b582c](https://github.com/ternbusty/takoyaki/commit/d9b582c4faad553fb2f657e0c796c1ab3d3522c2))
* **oci:** pass more validation tests — namespace path, rootfsPropagation, oom, rlimits ([da7807c](https://github.com/ternbusty/takoyaki/commit/da7807cd1e7b5b57d9b9b3c55f7a3088ae6c4f22))
* **rootfs:** add device creation via mknod with bind fallback ([c09ed80](https://github.com/ternbusty/takoyaki/commit/c09ed8028dceece4d3e8a8fd743cdbe08ca118d4))
* **rootfs:** add idmap mount primitive (open_tree + mount_setattr + move_mount) ([62c6941](https://github.com/ternbusty/takoyaki/commit/62c69417045596e2610cd7b1eb90801b7f715669))
* **rootfs:** auto-generate /etc/passwd and /etc/group entries ([74587a3](https://github.com/ternbusty/takoyaki/commit/74587a36b4b672561a4487511734104cd0510330))
* **rootfs:** default MS_NOSUID on rootfs bind ([89706b5](https://github.com/ternbusty/takoyaki/commit/89706b5e799441aeb6a3c7e6a2b41b81ce61215d))
* **rootfs:** mask sensitive paths and read-only remount paths ([4897162](https://github.com/ternbusty/takoyaki/commit/4897162315244a108845431d751deb3a2b07cfd3))
* **rootfs:** wire idmap mount via helper-spawned user namespace ([53ad779](https://github.com/ternbusty/takoyaki/commit/53ad7790c98f4958d9a3fc212a56cf49710441f1))
* **rootless:** use newuidmap/newgidmap helpers for multi-range maps ([b80af02](https://github.com/ternbusty/takoyaki/commit/b80af0217605591eedc76d039099cf4e64097198))
* **seccomp:** forward SCMP_ACT_NOTIFY fd to listenerPath via host-prepared socket ([cee91c1](https://github.com/ternbusty/takoyaki/commit/cee91c1f4af14395ed4666ecbf0dcdec57008973))
* **seccomp:** support arg-conditional rules and report notify fd ([adea061](https://github.com/ternbusty/takoyaki/commit/adea06109c5423ae103fc691753f0a0931e97d66))
* **security:** join new kernel session keyring per container ([3a9d185](https://github.com/ternbusty/takoyaki/commit/3a9d18597ccb9f947af357d89082c6eb9995a3ba))
* **selinux:** apply selinuxLabel via /proc/self/attr/exec ([0d25da5](https://github.com/ternbusty/takoyaki/commit/0d25da56eaeb8b620a2805c264b69bd6f52da12e))
* **spec:** add cpuset/timeOffsets/deviceCgroup/per-mount-propagation fields ([5736072](https://github.com/ternbusty/takoyaki/commit/57360727b7e808850f79a1ee1aff00e11fa88d29))
* **spec:** add hooks, annotations, sysctl, apparmor fields to oci spec ([72bd492](https://github.com/ternbusty/takoyaki/commit/72bd492d7bbc36c5a026f0972872d106b1d4ba9f))
* **syscall:** add setresuid/setresgid, mknod, ioctl wrappers ([be8ec32](https://github.com/ternbusty/takoyaki/commit/be8ec321f12048fa142e25e44632200723472f71))
* **sysctl:** add module to apply oci linux.sysctl to /proc/sys ([e8c248c](https://github.com/ternbusty/takoyaki/commit/e8c248c97d8e08a301bf0a7dafc2eb00a042002f))
* **time-ns:** apply linux.timeOffsets to /proc/self/timens_offsets ([632de84](https://github.com/ternbusty/takoyaki/commit/632de8486fb7c4a94de3f8f85c011841368874c7))


### 🐛 Bug Fixes

* **apparmor:** drop securityfs presence check that always fails post-pivot ([458a967](https://github.com/ternbusty/takoyaki/commit/458a9677aaf772564d0a7d06b6b6f375e8a54548))
* **apparmor:** try /proc/self/attr/apparmor/exec before legacy attr/exec ([881d242](https://github.com/ternbusty/takoyaki/commit/881d242bd1c5265ad2388077382e973a572bb59a))
* **devices,ci:** pre-pend OCI default device allows; flatten tarball; skip v1 cgroup tests ([dc11130](https://github.com/ternbusty/takoyaki/commit/dc1113032f70a33bfa7a900ef7ee1a1d235a5793))
* **idmap:** set up helper userns from main process, swap uid_map direction ([7ed1831](https://github.com/ternbusty/takoyaki/commit/7ed183198ca0db2417efee67f9dabcc8e4e0de85))
* **native-image:** register seccomp_rule_add_array foreign descriptor ([4cb86e5](https://github.com/ternbusty/takoyaki/commit/4cb86e5fd5b23e819818842da66674db5843183f))
* preserve MS_NOSUID across readonly remount; resolve bundle to absolute path ([e4253a5](https://github.com/ternbusty/takoyaki/commit/e4253a53fda9d262d572641f8adede07d0181d2e))
* **timens,bind-ro:** apply timens offsets pre-exec; remount bind for access flags ([33df491](https://github.com/ternbusty/takoyaki/commit/33df49187414f90d272719d3f430bf9a129e3c29))


### 🔧 Miscellaneous Chores

* configure native-image ffm downcalls and jackson reflection ([285e381](https://github.com/ternbusty/takoyaki/commit/285e3811702bd0a91752963749ca896b190cb7be))
* register ffm descriptors for pty, sendmsg, mknod, ioctl ([d84cc55](https://github.com/ternbusty/takoyaki/commit/d84cc5569f846f57d86a4adad00ff6bb3d35de96))
* scaffold gradle project with wrapper and build caching ([c26a50a](https://github.com/ternbusty/takoyaki/commit/c26a50a60a12c280e143d13f0ba82a7af5b5521d))
* **start:** surface spec-load errors and add poststart-hook debug log ([04bde1b](https://github.com/ternbusty/takoyaki/commit/04bde1b8ded4368e8518cb6a65cf893f079798f1))


### ♻️ Code Refactoring

* rename package from io.github.ternbusty.gcr to com.ternbusty.gcr ([408141a](https://github.com/ternbusty/takoyaki/commit/408141a51a0dbc00e5c595dbeb93124db708689f))
* rename project to takoyaki ([00c9961](https://github.com/ternbusty/takoyaki/commit/00c9961cc9d545c7b6767704d40de898c2625f57))
* **test:** adopt youki-style Syscalls trait + RecordingSyscalls fake ([59adf4a](https://github.com/ternbusty/takoyaki/commit/59adf4a75eabd0ecdce7a5e94ba60e2dea274c60))
