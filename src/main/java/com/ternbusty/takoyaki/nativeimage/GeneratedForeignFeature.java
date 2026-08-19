package com.ternbusty.takoyaki.nativeimage;

import org.graalvm.nativeimage.hosted.Feature;
import org.graalvm.nativeimage.hosted.RuntimeForeignAccess;

import java.lang.foreign.FunctionDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * Register every downcall the jextract-generated bindings declare.
 *
 * jextract emits one nested class per function holding a static
 * {@code FunctionDescriptor DESC}, so the whole set can be harvested by
 * reflection instead of being restated by hand in {@link ForeignFeature}.
 * Adding a function to a jextract task therefore needs no registration change.
 */
public final class GeneratedForeignFeature implements Feature {

    /**
     * Generated header classes to scan. Missing ones are skipped, so a branch
     * that has not migrated a given library yet still builds.
     */
    private static final String[] HEADER_CLASSES = {
            "com.ternbusty.takoyaki.syscall.posix.PosixH",
            "com.ternbusty.takoyaki.syscall.libc.LibcH",
            "com.ternbusty.takoyaki.syscall.libseccomp.SeccompH",
    };

    @Override
    public void duringSetup(DuringSetupAccess access) {
        int registered = 0;
        for (String name : HEADER_CLASSES) {
            Class<?> header;
            try {
                header = Class.forName(name, false, getClass().getClassLoader());
            } catch (ClassNotFoundException e) {
                continue;
            }
            for (Class<?> fn : header.getDeclaredClasses()) {
                for (Field f : fn.getDeclaredFields()) {
                    if (f.getType() != FunctionDescriptor.class
                            || !Modifier.isStatic(f.getModifiers())) {
                        continue;
                    }
                    try {
                        f.setAccessible(true);
                        RuntimeForeignAccess.registerForDowncall((FunctionDescriptor) f.get(null));
                        registered++;
                    } catch (Throwable t) {
                        // A descriptor we cannot read is left to ForeignFeature.
                    }
                }
            }
        }
        System.out.println("[GeneratedForeignFeature] registered " + registered + " downcalls");
    }
}
