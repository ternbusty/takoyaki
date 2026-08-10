import org.gradle.api.tasks.Exec
import java.time.Duration

plugins {
    application
    jacoco
    id("org.graalvm.buildtools.native") version "1.1.7"
}

group = "com.ternbusty"
// x-release-please-start-version
version = "0.3.1"
// x-release-please-end

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

dependencies {
    // No CLI parsing framework — Main.java hand-parses argv. picocli's
    // reflection-driven CommandSpec build cost ~80 ms on aarch64 native-image.
    // No JSON library — util.json hand-parses into a Map/List tree and the
    // Spec / State / KontainerConfig beans codec to/from it. jackson-databind
    // pulled in ~3,000 reachable methods and transitively ~4.6 MB of java.xml
    // at native-image build time, all for our small OCI schemas.
    compileOnly("org.graalvm.sdk:nativeimage:25.2.4")

    testImplementation(platform("org.junit:junit-bom:6.1.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.23.0")
}

application {
    mainClass = "com.ternbusty.takoyaki.Main"
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(
        listOf(
            "--enable-preview",
        ),
    )
    options.release = 25
}

tasks.named<JavaExec>("run") {
    jvmArgs("--enable-native-access=ALL-UNNAMED", "--enable-preview")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    // -Xshare:off keeps Mockito's bytecode manipulation happy on recent JDKs;
    // ByteBuddyAgent attach needs to be unconditionally allowed in tests.
    jvmArgs(
        "--enable-preview",
        "--enable-native-access=ALL-UNNAMED",
        "-XX:+EnableDynamicAgentLoading",
        "-Xshare:off",
    )
    // Contest tests live under com.ternbusty.takoyaki.contest and drive the
    // real takoyaki binary (needs TAKOYAKI_BIN set and Linux). They run via
    // the separate `contestTest` task — not as part of normal `./gradlew test`.
    exclude("com/ternbusty/takoyaki/contest/**")
    finalizedBy("jacocoTestReport")
}

// Integration tests modelled on youki's tests/contest. Each subpackage covers
// one OCI feature (cgroups, hooks, kill, lifecycle, ...). They invoke the
// already-built takoyaki binary against test bundles laid down under @TempDir.
// Skip locally if TAKOYAKI_BIN isn't set; CI sets it after the native build.
val contestTest by tasks.registering(Test::class) {
    description = "Run contest-style integration tests against the real takoyaki binary."
    group = "verification"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform()
    jvmArgs(
        "--enable-preview",
        "--enable-native-access=ALL-UNNAMED",
        "-XX:+EnableDynamicAgentLoading",
        "-Xshare:off",
    )
    // Only the contest package.
    include("com/ternbusty/takoyaki/contest/**")
    // Propagate the binary path to the test JVM so the harness can find it.
    System.getenv("TAKOYAKI_BIN")?.let { environment("TAKOYAKI_BIN", it) }
    // Hard ceiling on the whole task. The contest suite has ~30 scenarios
    // each shelling out to the native binary; a hung container init would
    // otherwise consume the full GitHub Actions job timeout. 15 min covers
    // the full run with healthy headroom (VM measures ~21 min total but
    // CI hardware is faster).
    timeout.set(Duration.ofMinutes(15))
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn("test")
    reports {
        xml.required = true
        html.required = true
    }
}

val bootstrapDir = layout.projectDirectory.dir("src/main/c/bootstrap")
val bootstrapBuildDir = layout.buildDirectory.dir("bootstrap")

// -Pmusl=1 switches the native build to musl libc + fully static linking,
// which collapses pre-main wall time (no glibc locale init, no dynamic
// loader work) at the cost of needing musl-tools, a musl-built libseccomp,
// and (later) a musl-built libz on the build machine. Default OFF so a
// stock Ubuntu + libseccomp-dev install still builds.
val useMusl = providers.gradleProperty("musl").isPresent
// Root of the musl prefix, ie. the --prefix passed to configure when
// building libseccomp / libz against musl-gcc. Default matches the VM
// layout documented in scripts/build-musl-deps.sh; override with
// -PmuslDepsDir=/path on the gradle command line.
val muslDepsDir = providers.gradleProperty("muslDepsDir").orElse("/home/ubuntu/musl-deps/prefix").get()

val buildBootstrap by tasks.registering(Exec::class) {
    val outDir = bootstrapBuildDir.get().asFile
    doFirst { outDir.mkdirs() }
    workingDir = bootstrapDir.asFile
    inputs.dir(bootstrapDir)
    inputs.property("useMusl", useMusl)
    outputs.dir(bootstrapBuildDir)
    val cc = if (useMusl) "musl-gcc" else "gcc"
    commandLine(
        "sh", "-c",
        "$cc -c -fPIC -Wall -Wextra -O2 bootstrap.c -o ${outDir.absolutePath}/bootstrap.o " +
            "&& ar rcs ${outDir.absolutePath}/libbootstrap.a ${outDir.absolutePath}/bootstrap.o",
    )
}

// Generate the libseccomp bindings (SeccompH + scmp_arg_cmp) from the system
// headers with jextract at build time. Not committed: the output is
// regenerated per build, so it always matches the build machine's arch (syscall
// numbers, struct layouts) instead of freezing one arch into the repo. Needs
// jextract on PATH, at ~/.sdkman/candidates/jextract/current/bin, or -Pjextract=.
val jextractDir = layout.buildDirectory.dir("generated/jextract")
val jextractBin = providers.gradleProperty("jextract").orElse(
    providers.provider {
        val sdk = file(System.getProperty("user.home") + "/.sdkman/candidates/jextract/current/bin/jextract")
        if (sdk.exists()) sdk.absolutePath else "jextract"
    })
val jextractSeccomp by tasks.registering(Exec::class) {
    val header = layout.projectDirectory.file("src/main/c/jextract/seccomp.h")
    inputs.file(header)
    inputs.property("jextract", jextractBin)
    outputs.dir(jextractDir)
    val functions = listOf(
        "seccomp_init", "seccomp_release", "seccomp_rule_add", "seccomp_rule_add_array",
        "seccomp_load", "seccomp_notify_fd", "seccomp_syscall_resolve_name",
        "seccomp_arch_add", "seccomp_arch_remove", "seccomp_arch_resolve_name", "seccomp_attr_set",
    )
    // Filter attributes, actions and comparison ops. Taking these from the
    // header matters: the enum has gaps (SCMP_FLTATR_API_TSKIP sits between
    // CTL_TSYNC and CTL_LOG), which hand-counted values get wrong.
    val constants = listOf(
        "SCMP_FLTATR_CTL_NNP", "SCMP_FLTATR_CTL_TSYNC", "SCMP_FLTATR_CTL_LOG",
        "SCMP_FLTATR_CTL_SSB", "SCMP_FLTATR_CTL_OPTIMIZE",
        "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL", "SCMP_ACT_TRAP",
        "SCMP_ACT_NOTIFY", "SCMP_ACT_LOG", "SCMP_ACT_ALLOW",
        "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_EQ", "SCMP_CMP_GE",
        "SCMP_CMP_GT", "SCMP_CMP_MASKED_EQ",
        "__NR_SCMP_ERROR",
        // ERRNO/TRACE are function-like macros; seccomp.h wraps their zero-arg
        // expansion in an enum so the base values stay header-derived.
        "TAKOYAKI_SCMP_ACT_ERRNO_BASE", "TAKOYAKI_SCMP_ACT_TRACE_BASE",
    )
    commandLine(buildList {
        add(jextractBin.get())
        add("--output"); add(jextractDir.get().asFile.absolutePath)
        add("-t"); add("com.ternbusty.takoyaki.syscall.libseccomp")
        add("--header-class-name"); add("SeccompH")
        add("-l"); add(":libseccomp.so.2")
        functions.forEach { add("--include-function"); add(it) }
        constants.forEach { add("--include-constant"); add(it) }
        add("--include-struct"); add("scmp_arg_cmp")
        add(header.asFile.absolutePath)
    })
}
// The libc headers pull in arch-specific bits from /usr/include/<triplet>;
// derive the triplet so the build works on aarch64 and x86_64 alike.
val multiarch = providers.exec { commandLine("gcc", "-print-multiarch") }
    .standardOutput.asText.map(String::trim)

val jextractLibc by tasks.registering(Exec::class) {
    val header = layout.projectDirectory.file("src/main/c/jextract/libc.h")
    inputs.file(header)
    inputs.property("jextract", jextractBin)
    inputs.property("multiarch", multiarch)
    outputs.dir(jextractDir)
    val functions = listOf(
        "unshare", "setns", "mount", "umount2", "chdir", "sethostname",
        "kill", "prctl", "umask", "getpid", "getppid", "__errno_location", "strerror",
        "execvp", "clearenv", "setenv", "setgroups", "prlimit64", "syscall", "geteuid",
        "getegid", "setresuid", "setresgid", "mknod", "ioctl", "waitpid",
    )
    commandLine(buildList {
        add(jextractBin.get())
        add("--output"); add(jextractDir.get().asFile.absolutePath)
        add("-t"); add("com.ternbusty.takoyaki.syscall.libc")
        add("--header-class-name"); add("LibcH")
        add("-I"); add("/usr/include/" + multiarch.get())
        functions.forEach { add("--include-function"); add(it) }
        add(header.asFile.absolutePath)
    })
}

val jextractConsts by tasks.registering(Exec::class) {
    val header = layout.projectDirectory.file("src/main/c/jextract/consts.h")
    inputs.file(header)
    inputs.property("jextract", jextractBin)
    outputs.dir(jextractDir)
    val constants = listOf(
        // syscall numbers
        "SYS_capset", "SYS_close_range", "SYS_pivot_root", "SYS_keyctl", "SYS_bpf",
        // namespaces
        "CLONE_NEWNS", "CLONE_NEWUTS", "CLONE_NEWIPC", "CLONE_NEWUSER",
        "CLONE_NEWPID", "CLONE_NEWNET", "CLONE_NEWCGROUP", "CLONE_NEWTIME",
        // mount flags
        "MS_RDONLY", "MS_NOSUID", "MS_NODEV", "MS_NOEXEC", "MS_REMOUNT", "MS_BIND",
        "MS_REC", "MS_NOATIME", "MS_RELATIME", "MS_STRICTATIME", "MS_NOSYMFOLLOW",
        "MS_PRIVATE", "MS_SLAVE", "MS_SHARED", "MS_UNBINDABLE", "MNT_DETACH",
        // prctl
        "PR_SET_DUMPABLE", "PR_SET_KEEPCAPS", "PR_SET_NO_NEW_PRIVS", "PR_CAPBSET_DROP",
        "PR_CAP_AMBIENT", "PR_CAP_AMBIENT_RAISE", "PR_CAP_AMBIENT_CLEAR_ALL",
        "PR_SET_CHILD_SUBREAPER",
        // signals
        "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGABRT", "SIGFPE", "SIGKILL",
        "SIGSEGV", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGUSR1", "SIGUSR2", "SIGCHLD",
        "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU",
        // errno
        "EPERM", "ENOENT", "ESRCH", "EINTR", "EEXIST", "EBUSY", "EINVAL", "ENOSYS",
        // sockets / files
        "AF_UNIX", "AF_INET", "SOCK_STREAM", "SOCK_DGRAM",
        "F_OK", "O_RDONLY", "O_RDWR", "O_CREAT", "O_DIRECTORY",
        "F_GETFD", "F_SETFD", "FD_CLOEXEC",
        // rlimits
        "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_CORE",
        "RLIMIT_RSS", "RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_MEMLOCK", "RLIMIT_AS",
        "RLIMIT_LOCKS", "RLIMIT_SIGPENDING", "RLIMIT_MSGQUEUE", "RLIMIT_NICE",
        "RLIMIT_RTPRIO", "RLIMIT_RTTIME",
        // misc
        "_LINUX_CAPABILITY_VERSION_3", "CLOSE_RANGE_CLOEXEC",
        "SIOCGIFFLAGS", "SIOCSIFFLAGS", "IFF_UP",
        "S_IFCHR", "S_IFBLK", "S_IFIFO",
        "KEYCTL_JOIN_SESSION_KEYRING",
    )
    commandLine(buildList {
        add(jextractBin.get())
        add("--output"); add(jextractDir.get().asFile.absolutePath)
        add("-t"); add("com.ternbusty.takoyaki.syscall.hdr")
        add("--header-class-name"); add("Consts")
        constants.forEach { add("--include-constant"); add(it) }
        add(header.asFile.absolutePath)
    })
}

sourceSets["main"].java.srcDir(jextractDir)
tasks.named<JavaCompile>("compileJava") { dependsOn(jextractSeccomp, jextractLibc, jextractConsts) }

// Pass -Pquick to gradle for a fast (-Ob) development build.
// Without -Pquick, a fully optimized image is produced.
val isQuick = providers.gradleProperty("quick").isPresent

graalvmNative {
    binaries {
        named("main") {
            imageName = "takoyaki"
            mainClass = "com.ternbusty.takoyaki.Main"
            quickBuild = isQuick
            // Linker option for libseccomp. glibc build links the system
            // shared library; musl build pulls in the static archive we
            // produced ourselves at $muslDepsDir/lib/libseccomp.a.
            val seccompLinkerOpt = if (useMusl) {
                "-H:NativeLinkerOption=$muslDepsDir/lib/libseccomp.a"
            } else {
                "-H:NativeLinkerOption=-Wl,--push-state,--no-as-needed,-l:libseccomp.so.2,--pop-state"
            }
            buildArgs.addAll(
                "--no-fallback",
                "-O3",
                // JFR/heapdump monitoring drops image heap by a few hundred
                // KB and avoids any JFR-related <clinit> work at runtime.
                // takoyaki is short-lived; if you want JFR for an interactive
                // session use a JVM build instead of the native image.
                "-H:+UnlockExperimentalVMOptions",
                "-H:+ForeignAPISupport",
                "-H:+PrintImageHeapPartitionSizes",
                // Mostly-static: pull java/nio/net/zip etc. into the binary
                // statically. libc stays dynamic (musl static on aarch64 is
                // not supported by GraalVM; see issue #10375). Saves a few
                // ld.so DT_NEEDED resolutions at startup.
                "--static-nolibc",
                // Skip glibc system locale initialization at startup. With
                // it on, SubstrateVM's LocaleSupport.initialize() calls into
                // glibc which opens 28 LC_*/locale-archive files (~80 ms of
                // pre-main wall time on aarch64). takoyaki is a non-i18n CLI
                // and only needs the C locale, so we fall back to the
                // built-in "US/en" stub LocaleData. Has no effect on Java
                // Locale.getDefault() — that's a separate JDK code path.
                "-H:-UseSystemLocale",
                "-H:NativeLinkerOption=${bootstrapBuildDir.get().asFile.absolutePath}/libbootstrap.a",
                "-H:NativeLinkerOption=-rdynamic",
                "-H:NativeLinkerOption=-Wl,--whole-archive,${bootstrapBuildDir.get().asFile.absolutePath}/libbootstrap.a,--no-whole-archive",
                seccompLinkerOpt,
                "--features=com.ternbusty.takoyaki.nativeimage.ForeignFeature",
                "--enable-native-access=ALL-UNNAMED",
                "--enable-preview",
                // Build-time-initialize most of takoyaki. Classes that have
                // FFM downcalls in their <clinit> (Linker.nativeLinker(),
                // SymbolLookup.defaultLookup) must stay run-time because
                // SubstrateVM forbids native lookups at build time. Those
                // are listed via --initialize-at-run-time below.
                "--initialize-at-build-time=com.ternbusty.takoyaki",
                // Run-time init for FFM/native-using classes:
                "--initialize-at-run-time=com.ternbusty.takoyaki.util.Json",
                "--initialize-at-run-time=com.ternbusty.takoyaki.command.Wait",
                "--initialize-at-run-time=com.ternbusty.takoyaki.syscall",
                "--initialize-at-run-time=com.ternbusty.takoyaki.seccomp",
                "--initialize-at-run-time=com.ternbusty.takoyaki.syscall.libseccomp",
                "--initialize-at-run-time=com.ternbusty.takoyaki.ipc",
                "--initialize-at-run-time=com.ternbusty.takoyaki.console",
            )
            if (useMusl) {
                // --libc=musl plus --static produces a fully static
                // executable with no DT_NEEDED entries and no glibc
                // locale init at startup. Requires musl-tools and a
                // musl-built libseccomp + libz on the build machine.
                // -H:-CheckToolchain is needed on aarch64 because
                // native-image looks for a triplet-prefixed binary
                // ($arch-linux-musl-gcc) that Ubuntu does not ship;
                // the linker step uses musl-gcc directly anyway.
                buildArgs.addAll(
                    "--libc=musl",
                    "--static",
                    "-H:-CheckToolchain",
                    "-H:CLibraryPath=$muslDepsDir/lib",
                )
            }
        }
    }
}

tasks.named("nativeCompile") {
    dependsOn(buildBootstrap)
    // libbootstrap.a only reaches the image via -H:NativeLinkerOption, which
    // Gradle cannot see as an input. Without this, a C-only change rebuilds
    // the archive but leaves nativeCompile UP-TO-DATE with the stale link.
    inputs.dir(bootstrapBuildDir)
}
