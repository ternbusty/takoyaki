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

    private static final String BASE_CLASS = "com.ternbusty.takoyaki.syscall.gen.NativeHRaw";

    @Override
    public void duringSetup(DuringSetupAccess access) {
        int registered = 0;
        ClassLoader cl = getClass().getClassLoader();

        for (int i = 0; ; i++) {
            String name = (i == 0) ? BASE_CLASS : BASE_CLASS + "_" + i;
            Class<?> header;
            try {
                header = Class.forName(name, false, cl);
            } catch (ClassNotFoundException e) {
                if (i == 0) throw new RuntimeException("base header class not found: " + BASE_CLASS, e);
                break;
            }
            registered += scanHeader(header);
        }
        System.out.println("[GeneratedForeignFeature] registered " + registered + " downcalls");
    }

    private static int scanHeader(Class<?> header) {
        int count = 0;
        for (Class<?> fn : header.getDeclaredClasses()) {
            for (Field f : fn.getDeclaredFields()) {
                if (f.getType() != FunctionDescriptor.class
                        || !Modifier.isStatic(f.getModifiers())) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    RuntimeForeignAccess.registerForDowncall((FunctionDescriptor) f.get(null));
                    count++;
                } catch (Throwable t) {
                    // A descriptor we cannot read is left to ForeignFeature.
                }
            }
        }
        return count;
    }
}
