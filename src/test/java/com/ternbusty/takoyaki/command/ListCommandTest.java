package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ListCommandTest {

    private final PrintStream realStdout = System.out;
    private ByteArrayOutputStream captured;

    @BeforeEach
    void captureStdout() {
        captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured));
    }

    @AfterEach
    void restoreStdout() {
        System.setOut(realStdout);
    }

    @Test
    void emptyRootDirectoryPrintsEmptyJsonInJsonMode(@TempDir Path tmp) {
        // No containers saved yet. The runtime-tools list adapter expects
        // a JSON array for empty, not absent output. Json.encode may emit
        // either "[]" or "[ ]" depending on pretty-printer setup, so accept
        // either as long as it parses to an empty array.
        int rc = ListCommand.run(tmp.toString(), "json", false);
        assertEquals(0, rc);
        String out = captured.toString().trim();
        assertTrue(out.equals("[]") || out.equals("[ ]"),
                () -> "expected empty JSON array, got: <" + out + ">");
    }

    @Test
    void missingDefaultRootDirectoryPrintsEmptyJson() {
        // /run/runc is a default root path that does not exist on a machine
        // without runc installed. The first invocation (before any create)
        // should return a valid "no containers" answer.
        int rc = ListCommand.run("/run/runc", "json", false);
        assertEquals(0, rc);
        assertEquals("[]\n", captured.toString());
    }

    @Test
    void missingNonDefaultRootDirectoryReturnsError() {
        // An explicit --root that does not exist is an error. The runtime
        // can't list containers from a directory that doesn't exist when it
        // is not the default path.
        PrintStream realErr = System.err;
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errBuf));
        try {
            int rc = ListCommand.run("/this/does/not/exist", "json", false);
            assertEquals(1, rc);
        } finally {
            System.setErr(realErr);
        }
    }

    @Test
    void quietFlagPrintsOnlyContainerIds(@TempDir Path tmp) throws IOException {
        saveState(tmp, "alpha");
        saveState(tmp, "beta");

        int rc = ListCommand.run(tmp.toString(), "table", true);
        assertEquals(0, rc);

        String out = captured.toString();
        // Quiet mode is the contract docker/podman scripts pipe into xargs.
        // Each line MUST be just the id, nothing else.
        assertTrue(out.contains("alpha"));
        assertTrue(out.contains("beta"));
        assertFalse(out.contains("PID"),    "quiet must NOT print headers");
        assertFalse(out.contains("STATUS"), "quiet must NOT print headers");
    }

    @Test
    void tableFormatPrintsHeaderAndOneRowPerContainer(@TempDir Path tmp) throws IOException {
        saveState(tmp, "ctr-1");

        int rc = ListCommand.run(tmp.toString(), "table", false);
        assertEquals(0, rc);

        String out = captured.toString();
        // Header columns are fixed-position, runc-compatible.
        assertTrue(out.contains("ID"));
        assertTrue(out.contains("PID"));
        assertTrue(out.contains("STATUS"));
        assertTrue(out.contains("CREATED"));
        assertTrue(out.contains("BUNDLE"));
        assertTrue(out.contains("ctr-1"));
    }

    @Test
    void unreadableChildDirectoriesAreSkippedNotFatal(@TempDir Path tmp) throws IOException {
        // A leftover dir from an aborted create that doesn't contain a
        // valid state.json must NOT break list — it's the only way the user
        // can find the container to delete it manually.
        saveState(tmp, "good");
        Files.createDirectories(tmp.resolve("garbage-dir"));
        // No state.json inside garbage-dir.

        int rc = ListCommand.run(tmp.toString(), "json", false);
        assertEquals(0, rc);
        String out = captured.toString();
        assertTrue(out.contains("good"));
        // Garbage entries must not poison the JSON output (jq/yaml/etc parse it).
        assertFalse(out.contains("garbage-dir"));
    }

    private static void saveState(Path root, String id) throws IOException {
        State s = State.create("1.0.0", id, ContainerStatus.CREATED, 1234,
                "/some/bundle", Map.of("k", "v"));
        s.save(root.toString());
    }
}
