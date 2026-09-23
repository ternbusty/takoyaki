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
        // jextract may split a large header into NativeH, NativeH_1, NativeH_2, ...
        // Iterate until we hit a class that does not exist.
        var i = 0
        while (true) {
            val name = if (i == 0) BASE_CLASS else "${BASE_CLASS}_$i"
            val header = try {
                Class.forName(name, false, javaClass.classLoader)
            } catch (_: ClassNotFoundException) {
                break
            }
            registered += scanHeader(header)
            i++
        }
        println("[GeneratedForeignFeature] registered $registered downcalls")
    }

    private fun scanHeader(header: Class<*>): Int {
        var count = 0
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
                    count++
                } catch (_: Throwable) {
                    // A descriptor we cannot read is left to ForeignFeature.
                }
            }
        }
        return count
    }

    companion object {
        /** Base class name for jextract-generated headers. */
        private const val BASE_CLASS = "com.ternbusty.takoyaki.syscall.gen.NativeH"
    }
}
