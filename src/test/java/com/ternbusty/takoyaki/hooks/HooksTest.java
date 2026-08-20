package com.ternbusty.takoyaki.hooks;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HooksTest {

    private State sampleState() {
        State s = new State();
        s.id = "ctr-a";
        s.status = "created";
        s.pid = 4242;
        s.bundle = "/tmp/bundle";
        return s;
    }

    private Spec.Hook hook(String path, List<String> args, Long timeout) {
        Spec.Hook h = new Spec.Hook();
        h.path = path;
        h.args = args;
        h.timeout = timeout;
        return h;
    }

    @Test
    void nullListIsNoOp() {
        // Hooks.run must tolerate a missing hook section without throwing —
        // many specs don't define any.
        assertDoesNotThrow(() -> Hooks.run(null, sampleState(), "prestart"));
    }

    @Test
    void emptyListIsNoOp() {
        assertDoesNotThrow(() -> Hooks.run(List.of(), sampleState(), "prestart"));
    }

    @Test
    void hookWithNullPathIsSkipped() {
        // A hook entry without a `path` is malformed but mustn't crash the
        // runtime — silently skip and continue with the remaining hooks.
        Spec.Hook bad = hook(null, null, 1L);
        assertDoesNotThrow(() -> Hooks.run(List.of(bad), sampleState(), "prestart"));
    }

    @Test
    void hookExecutesAndReceivesStateOnStdin(@TempDir Path tmp) throws IOException {
        // End-to-end: feed the hook a real shell script that captures stdin,
        // run it, and confirm the JSON-encoded state turned up there. This is
        // the contract that runtime-tools' hooks_stdin test enforces.
        Path script = tmp.resolve("hook.sh");
        Path output = tmp.resolve("stdin.txt");
        Files.writeString(script, """
                #!/bin/sh
                cat > "%s"
                """.formatted(output));
        script.toFile().setExecutable(true);

        Spec.Hook h = hook(script.toString(), List.of(script.toString()), 5L);
        Hooks.run(List.of(h), sampleState(), "prestart");

        assertTrue(Files.exists(output), "hook should have written its stdin");
        String got = Files.readString(output);
        assertTrue(got.contains("\"id\""),     "state JSON missing id: " + got);
        assertTrue(got.contains("\"ctr-a\""),  "state JSON missing id value");
        assertTrue(got.contains("\"pid\""),    "state JSON missing pid field");
        assertTrue(got.contains("4242"),       "state JSON missing pid value");
    }

    @Test
    void hookExitNonZeroIsNotFatal(@TempDir Path tmp) throws IOException {
        // A failing hook is logged but mustn't crash the runtime (matches
        // runc — only failures of "prestart" hooks block container start,
        // which the caller decides, not Hooks.run itself).
        Path script = tmp.resolve("fail.sh");
        Files.writeString(script, """
                #!/bin/sh
                cat > /dev/null
                exit 7
                """);
        script.toFile().setExecutable(true);

        Spec.Hook h = hook(script.toString(), List.of("fail.sh"), 5L);
        assertDoesNotThrow(() -> Hooks.run(List.of(h), sampleState(), "poststart"));
    }

    @Test
    void hookTimeoutIsHonoured(@TempDir Path tmp) throws IOException {
        // The OCI spec lets hooks specify a `timeout` in seconds. After that
        // we must SIGKILL the hook so a buggy script can't wedge container
        // lifecycle forever.
        Path script = tmp.resolve("slow.sh");
        Files.writeString(script, """
                #!/bin/sh
                cat > /dev/null
                sleep 30
                """);
        script.toFile().setExecutable(true);

        Spec.Hook h = hook(script.toString(), List.of("slow.sh"), 1L /* 1s */);
        long start = System.currentTimeMillis();
        Hooks.run(List.of(h), sampleState(), "poststop");
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < 5_000,
                "timeout must have terminated the slow hook, but took " + elapsed + "ms");
    }
}
