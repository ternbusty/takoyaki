package com.ternbusty.takoyaki.nativeimage

import org.graalvm.nativeimage.hosted.Feature
import org.graalvm.nativeimage.hosted.Feature.DuringSetupAccess
import org.graalvm.nativeimage.hosted.RuntimeForeignAccess

import java.lang.foreign.FunctionDescriptor
import java.lang.reflect.Modifier

/**
 * Register every downcall the jextract-generated bindings declare.
 *
 * jextract emits one nested class per function holding a static
 * `FunctionDescriptor DESC`, so the whole set can be harvested by
 * reflection instead of being restated by hand in [ForeignFeature].
 * Adding a function to a jextract task therefore needs no registration change.
 */
class GeneratedForeignFeature : Feature {

    override fun duringSetup(access: DuringSetupAccess) {
        var registered = 0
        for (name in HEADER_CLASSES) {
            val header = try {
                Class.forName(name, false, javaClass.classLoader)
            } catch (_: ClassNotFoundException) {
                continue
            }
            for (fn in header.declaredClasses) {
                for (f in fn.declaredFields) {
                    if (f.type != FunctionDescriptor::class.java
                        || !Modifier.isStatic(f.modifiers)
                    ) {
                        continue
                    }
                    try {
                        f.isAccessible = true
                        RuntimeForeignAccess.registerForDowncall(f.get(null) as FunctionDescriptor)
                        registered++
                    } catch (_: Throwable) {
                        // A descriptor we cannot read is left to ForeignFeature.
                    }
                }
            }
        }
        println("[GeneratedForeignFeature] registered $registered downcalls")
    }

    companion object {
        /**
         * Generated header classes to scan. Missing ones are skipped, so a branch
         * that has not migrated a given library yet still builds.
         */
        private val HEADER_CLASSES = arrayOf(
            "com.ternbusty.takoyaki.syscall.gen.NativeH",
        )
    }
}
