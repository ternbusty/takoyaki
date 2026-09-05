package com.ternbusty.takoyaki.util

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

object JsonCodec {

    val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
    }

    val prettyJson = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
        prettyPrint = true
    }

    @Throws(IOException::class)
    inline fun <reified T> loadFromFile(path: Path): T =
        json.decodeFromString(Files.readString(path))

    @Throws(IOException::class)
    inline fun <reified T> saveToFile(path: Path, value: T) {
        Files.writeString(path, prettyJson.encodeToString(value))
    }

    inline fun <reified T> encode(value: T): String =
        prettyJson.encodeToString(value)

    inline fun <reified T> encodeCompact(value: T): String =
        json.encodeToString(value)

    inline fun <reified T> decode(s: String): T =
        json.decodeFromString(s)

    fun encodePretty(element: JsonElement): String =
        prettyJson.encodeToString(JsonElement.serializer(), element)

    fun encodeCompact(element: JsonElement): String =
        json.encodeToString(JsonElement.serializer(), element)

    fun toJsonElement(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is JsonElement -> value
        is String -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is Int -> JsonPrimitive(value)
        is Long -> JsonPrimitive(value)
        is Double -> JsonPrimitive(value)
        is Map<*, *> -> JsonObject(value.entries.associate { (k, v) -> k.toString() to toJsonElement(v) })
        is List<*> -> JsonArray(value.map { toJsonElement(it) })
        else -> JsonPrimitive(value.toString())
    }
}
