package com.ternbusty.takoyaki.util.json

/**
 * Type-safe accessors for the [JsonParser]-shaped tree, plus list/map
 * helpers used by the per-class codecs in `spec/`, `state/`,
 * and `config/`.
 *
 * The accessors return `null` when the key is absent so that the
 * caller can decide whether the field is optional. Primitive variants
 * ([longOr], [intOr], [boolOr]) take a default for
 * fields that aren't nullable in the bean.
 *
 * Type mismatches throw [IllegalStateException] with a helpful
 * pointer to the offending key — this is the same shape jackson's
 * `MismatchedInputException` surfaces, just without the stack.
 */
object JsonMap {

    @Suppress("UNCHECKED_CAST")
    fun asObject(node: Any?): MutableMap<String, Any?>? {
        if (node == null) return null
        if (node is Map<*, *>) return node as MutableMap<String, Any?>
        throw IllegalStateException("expected JSON object, got ${typeName(node)}")
    }

    @Suppress("UNCHECKED_CAST")
    fun asArray(node: Any?): MutableList<Any?>? {
        if (node == null) return null
        if (node is List<*>) return node as MutableList<Any?>
        throw IllegalStateException("expected JSON array, got ${typeName(node)}")
    }

    fun str(o: Map<String, Any?>, key: String): String? {
        val v = o[key] ?: return null
        if (v is String) return v
        throw IllegalStateException("expected string at '$key', got ${typeName(v)}")
    }

    fun longBoxed(o: Map<String, Any?>, key: String): Long? {
        val v = o[key] ?: return null
        if (v is Long) return v
        if (v is Number) return v.toLong()
        throw IllegalStateException("expected number at '$key', got ${typeName(v)}")
    }

    fun longOr(o: Map<String, Any?>, key: String, def: Long): Long =
        longBoxed(o, key) ?: def

    fun intBoxed(o: Map<String, Any?>, key: String): Int? =
        longBoxed(o, key)?.toInt()

    fun intOr(o: Map<String, Any?>, key: String, def: Int): Int =
        intBoxed(o, key) ?: def

    fun boolBoxed(o: Map<String, Any?>, key: String): Boolean? {
        val v = o[key] ?: return null
        if (v is Boolean) return v
        throw IllegalStateException("expected boolean at '$key', got ${typeName(v)}")
    }

    fun boolOr(o: Map<String, Any?>, key: String, def: Boolean): Boolean =
        boolBoxed(o, key) ?: def

    fun strList(o: Map<String, Any?>, key: String): MutableList<String?>? {
        val a = asArray(o[key]) ?: return null
        val r = ArrayList<String?>(a.size)
        for (v in a) {
            if (v != null && v !is String) {
                throw IllegalStateException("expected string in '$key' array, got ${typeName(v)}")
            }
            r.add(v as String?)
        }
        return r
    }

    fun intList(o: Map<String, Any?>, key: String): MutableList<Int>? {
        val a = asArray(o[key]) ?: return null
        val r = ArrayList<Int>(a.size)
        for (v in a) {
            if (v is Number) r.add(v.toInt())
            else throw IllegalStateException("expected int in '$key' array, got ${typeName(v)}")
        }
        return r
    }

    fun <T> list(o: Map<String, Any?>, key: String, mapper: (Any?) -> T): MutableList<T>? {
        val a = asArray(o[key]) ?: return null
        val r = ArrayList<T>(a.size)
        for (v in a) r.add(mapper(v))
        return r
    }

    fun strMap(o: Map<String, Any?>, key: String): MutableMap<String, String?>? {
        val m = asObject(o[key]) ?: return null
        val r = LinkedHashMap<String, String?>()
        for ((k, v) in m) {
            if (v != null && v !is String) {
                throw IllegalStateException("expected string in '$key' map, got ${typeName(v)}")
            }
            r[k] = v as String?
        }
        return r
    }

    fun <T> map(o: Map<String, Any?>, key: String, mapper: (Any?) -> T): MutableMap<String, T>? {
        val m = asObject(o[key]) ?: return null
        val r = LinkedHashMap<String, T>()
        for ((k, v) in m) {
            r[k] = mapper(v)
        }
        return r
    }

    /** Builds a Map ready for [JsonWriter]; null values are skipped. */
    fun obj(): MutableMap<String, Any?> = LinkedHashMap()

    /** `put` that drops null values — gives us jackson NON_NULL semantics. */
    fun put(o: MutableMap<String, Any?>, key: String, value: Any?) {
        if (value != null) o[key] = value
    }

    /** Like [put] but always emits the key (used for `false` etc. that we want explicit). */
    fun putAlways(o: MutableMap<String, Any?>, key: String, value: Any?) {
        o[key] = value
    }

    /** Encodes a list of bean-backed objects via their `toJson` method. */
    fun <T> encList(items: List<T>?, mapper: (T) -> Any?): MutableList<Any?>? {
        if (items == null) return null
        val r = ArrayList<Any?>(items.size)
        for (item in items) r.add(mapper(item))
        return r
    }

    private fun typeName(v: Any?): String = v?.javaClass?.simpleName ?: "null"
}
