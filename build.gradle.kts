import org.gradle.api.tasks.Exec
import java.time.Duration

plugins {
    application
    jacoco
    id("org.graalvm.buildtools.native") version "1.1.13"
}

group = "com.ternbusty"
// x-release-please-start-version
version = "0.4.1"
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
    compileOnly("org.graalvm.sdk:nativeimage:25.3.4.1")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
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
val arch = System.getProperty("os.arch")   // "amd64" or "aarch64"
val useMusl = providers.gradleProperty("musl").isPresent.also {
    if (it && arch == "aarch64") {
        throw GradleException(
            "-Pmusl is not supported on aarch64: GraalVM does not ship " +
            "static JDK libraries for musl on this architecture (see oracle/graal#10375). " +
            "Use the default glibc (--static-nolibc) build instead."
        )
    }
}
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
        "$cc -c -fPIC -Wall -Wextra -O2 ${if (useMusl) "-DTAKOYAKI_STATIC " else ""}bootstrap.c -o ${outDir.absolutePath}/bootstrap.o " +
            (if (useMusl)
                "&& $cc -c -fPIC -Wall -Wextra -O2 static_lookup.c -o ${outDir.absolutePath}/static_lookup.o " +
                "&& ar rcs ${outDir.absolutePath}/libbootstrap.a ${outDir.absolutePath}/bootstrap.o ${outDir.absolutePath}/static_lookup.o"
            else
                "&& ar rcs ${outDir.absolutePath}/libbootstrap.a ${outDir.absolutePath}/bootstrap.o"),
    )
}

// Generate FFM bindings from the system headers with jextract at build time.
// Not committed: the output is regenerated per build, so it always matches
// the build machine's arch (syscall numbers, struct layouts) instead of
// freezing one arch into the repo. Needs jextract on PATH, at
// ~/.sdkman/candidates/jextract/current/bin, or -Pjextract=.
val jextractDir = layout.buildDirectory.dir("generated/jextract")
val jextractBin = providers.gradleProperty("jextract").orElse(
    providers.provider {
        val sdk = file(System.getProperty("user.home") + "/.sdkman/candidates/jextract/current/bin/jextract")
        if (sdk.exists()) sdk.absolutePath else "jextract"
    })
// The libc headers pull in arch-specific bits from /usr/include/<triplet>;
// derive the triplet so the build works on aarch64 and x86_64 alike.
val multiarch = providers.exec { commandLine("gcc", "-print-multiarch") }
    .standardOutput.asText.map(String::trim)

val jextractNative by tasks.registering(Exec::class) {
    val header = layout.projectDirectory.file("src/main/c/jextract/native.h")
    inputs.file(header)
    inputs.property("jextract", jextractBin)
    inputs.property("multiarch", multiarch)
    outputs.dir(jextractDir)
    commandLine(buildList {
        add(jextractBin.get())
        add("--output"); add(jextractDir.get().asFile.absolutePath)
        add("-t"); add("com.ternbusty.takoyaki.syscall.gen")
        // NativeH itself is generated by generateFastBindings on top of this.
        add("--header-class-name"); add("NativeHRaw")
        add("-l"); add(":libseccomp.so.2")
        add("-I"); add("/usr/include/" + multiarch.get())
        add(header.asFile.absolutePath)
    })
}

// In the musl (fully-static) build, replace jextract's SYMBOL_LOOKUP with
// StaticSymbolLookup which uses a C lookup table instead of dlopen/dlsym.
// dlopen is non-functional in a static musl binary, so all three standard
// FFM lookup paths (libraryLookup, loaderLookup, defaultLookup) fail.
val patchJextractForMusl by tasks.registering {
    val muslBuild = useMusl
    val jextDir = jextractDir
    dependsOn(jextractNative)
    onlyIf { muslBuild }
    doLast {
        val genDir = jextDir.get().asFile.resolve("com/ternbusty/takoyaki/syscall/gen")
        val pattern = Regex("""static final SymbolLookup SYMBOL_LOOKUP = SymbolLookup\.libraryLookup\([^;]+;""")
        genDir.listFiles()?.filter { it.name.startsWith("NativeHRaw_") && it.extension == "java" }?.forEach { file ->
            val original = file.readText()
            val patched = original.replace(
                pattern,
                "static final SymbolLookup SYMBOL_LOOKUP = com.ternbusty.takoyaki.nativeimage.StaticSymbolLookup.INSTANCE;"
            )
            if (patched != original) {
                file.writeText(patched)
                logger.lifecycle("Patched ${file.name} SYMBOL_LOOKUP for static build")
            }
        }
    }
}

// The jextract output is compiled on its own so that generateFastBindings can
// read it by reflection before the main sources are compiled.
val jextractSourceSet = sourceSets.create("jextract") { java.srcDir(jextractDir) }
tasks.named<JavaCompile>(jextractSourceSet.compileJavaTaskName) { dependsOn(jextractNative, patchJextractForMusl) }
dependencies { implementation(jextractSourceSet.output) }

// Build-time generator for constant downcall handles (see GenerateFastBindings).
// It writes NativeH (extends the jextract NativeHRaw) and ffi.Downcalls.
val ffigenSourceSet = sourceSets.create("ffigen")
val fastBindingsDir = layout.buildDirectory.dir("generated/fastbindings")
val generateFastBindings by tasks.registering(JavaExec::class) {
    classpath = ffigenSourceSet.output + jextractSourceSet.output
    mainClass = "com.ternbusty.takoyaki.ffigen.GenerateFastBindings"
    javaLauncher = javaToolchains.launcherFor(java.toolchain)
    jvmArgs("--enable-native-access=ALL-UNNAMED", "--enable-preview")
    inputs.files(ffigenSourceSet.output, jextractSourceSet.output)
    outputs.dir(fastBindingsDir)
    val outDir = fastBindingsDir
    doFirst { outDir.get().asFile.deleteRecursively() }
    // Variadic functions need their call shape fixed up front: name followed by
    // the layouts of the variadic arguments takoyaki passes.
    args(
        fastBindingsDir.get().asFile.absolutePath,
        "prctl:C_LONG,C_LONG,C_LONG,C_LONG",
        "syscall:C_LONG,C_LONG,C_LONG,C_LONG,C_LONG",
        "ioctl:C_POINTER",
        "open:C_INT",
        "fcntl:C_INT",
    )
}
sourceSets["main"].java.srcDir(fastBindingsDir)

// Generate BuildInfo.java so the binary reports the release-please managed
// project version (and the git commit) instead of a hand-maintained constant.
val buildInfoDir = layout.buildDirectory.dir("generated/buildinfo")
val generateBuildInfo by tasks.registering {
    // Capture everything the action needs as locals: referencing script-level
    // properties from doLast would drag the script object into the
    // configuration cache, which Gradle rejects.
    val outDir = buildInfoDir
    val projectVersion = project.version.toString()
    val gitCommit =
        try {
            providers.exec { commandLine("git", "rev-parse", "--short", "HEAD") }
                .standardOutput.asText.get().trim()
        } catch (_: Exception) {
            "unknown"
        }
    inputs.property("version", projectVersion)
    inputs.property("commit", gitCommit)
    outputs.dir(outDir)
    doLast {
        val dir = outDir.get().dir("com/ternbusty/takoyaki").asFile
        dir.mkdirs()
        dir.resolve("BuildInfo.java").writeText(
            """
            package com.ternbusty.takoyaki;

            /** Build-time constants. Generated by Gradle; do not edit. */
            public final class BuildInfo {
                public static final String VERSION = "$projectVersion";
                public static final String COMMIT = "$gitCommit";

                private BuildInfo() {}
            }
            """.trimIndent() + "\n",
        )
    }
}
sourceSets["main"].java.srcDir(buildInfoDir)
tasks.named<JavaCompile>("compileJava") { dependsOn(generateBuildInfo) }
tasks.named<JavaCompile>("compileJava") { dependsOn(generateFastBindings) }

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
                // Mostly-static (glibc) or fully static (musl): pull
                // java/nio/net/zip etc. into the binary statically. With
                // glibc, libc stays dynamic (musl static on aarch64 is not
                // supported by GraalVM; see issue #10375). With musl, libc
                // is also statically linked, eliminating all DT_NEEDED.
                if (useMusl) "--static" else "--static-nolibc",
                // Skip glibc system locale initialization at startup. With
                // it on, SubstrateVM's LocaleSupport.initialize() calls into
                // glibc which opens 28 LC_*/locale-archive files (~80 ms of
                // pre-main wall time on aarch64). takoyaki is a non-i18n CLI
                // and only needs the C locale, so we fall back to the
                // built-in "US/en" stub LocaleData. Has no effect on Java
                // Locale.getDefault() — that's a separate JDK code path.
                "-H:-UseSystemLocale",
                "-H:NativeLinkerOption=-rdynamic",
                "-H:NativeLinkerOption=-Wl,--whole-archive,${bootstrapBuildDir.get().asFile.absolutePath}/libbootstrap.a,--no-whole-archive",
                seccompLinkerOpt,
                "--features=com.ternbusty.takoyaki.nativeimage.ForeignFeature",
                "--features=com.ternbusty.takoyaki.nativeimage.GeneratedForeignFeature",
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
                "--initialize-at-run-time=com.ternbusty.takoyaki.syscall.gen",
                "--initialize-at-run-time=com.ternbusty.takoyaki.ipc",
                "--initialize-at-run-time=com.ternbusty.takoyaki.console",
                "--initialize-at-run-time=com.ternbusty.takoyaki.nativeimage.StaticSymbolLookup",
                "--initialize-at-run-time=com.ternbusty.takoyaki.ioloop",
                "-H:-EnableSecurityServicesFeature",
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
