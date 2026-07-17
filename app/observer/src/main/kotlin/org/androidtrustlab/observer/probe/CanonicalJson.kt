package org.androidtrustlab.observer.probe

import java.nio.charset.StandardCharsets

/** The bounded data model accepted by ATL Canonical JSON v1. */
sealed interface JsonValue

data object JsonNull : JsonValue
data class JsonBoolean(val value: Boolean) : JsonValue
data class JsonInteger(val value: Long) : JsonValue
data class JsonString(val value: String) : JsonValue
data class JsonArray(val values: List<JsonValue>) : JsonValue
data class JsonObject(val values: Map<String, JsonValue>) : JsonValue

/** Dependency-free canonical JSON encoder shared by artifact and manifest output. */
object CanonicalJson {
    private const val MAX_DEPTH = 32
    private const val MAX_NODES = 100_000
    private const val MAX_BYTES = 2 * 1024 * 1024
    private const val MAX_INTEROPERABLE_INTEGER = 9_007_199_254_740_991L

    fun encode(value: JsonValue): ByteArray {
        var nodes = 0
        fun append(current: JsonValue, output: StringBuilder, depth: Int) {
            nodes += 1
            require(nodes <= MAX_NODES) { "canonical JSON node limit exceeded" }
            require(depth <= MAX_DEPTH) { "canonical JSON nesting limit exceeded" }
            when (current) {
                JsonNull -> output.append("null")
                is JsonBoolean -> output.append(if (current.value) "true" else "false")
                is JsonInteger -> {
                    require(current.value in -MAX_INTEROPERABLE_INTEGER..MAX_INTEROPERABLE_INTEGER) {
                        "canonical JSON integer is not interoperable"
                    }
                    output.append(current.value)
                }
                is JsonString -> appendString(current.value, output)
                is JsonArray -> {
                    output.append('[')
                    current.values.forEachIndexed { index, item ->
                        if (index > 0) output.append(',')
                        append(item, output, depth + 1)
                    }
                    output.append(']')
                }
                is JsonObject -> {
                    output.append('{')
                    current.values.toSortedMap().entries.forEachIndexed { index, entry ->
                        if (index > 0) output.append(',')
                        appendString(entry.key, output)
                        output.append(':')
                        append(entry.value, output, depth + 1)
                    }
                    output.append('}')
                }
            }
        }

        val output = StringBuilder()
        append(value, output, 0)
        val bytes = output.toString().toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= MAX_BYTES) { "canonical JSON byte limit exceeded" }
        return bytes
    }

    private fun appendString(value: String, output: StringBuilder) {
        output.append('"')
        var index = 0
        while (index < value.length) {
            val character = value[index]
            when (character) {
                '"' -> output.append("\\\"")
                '\\' -> output.append("\\\\")
                '\b' -> output.append("\\b")
                '\u000c' -> output.append("\\f")
                '\n' -> output.append("\\n")
                '\r' -> output.append("\\r")
                '\t' -> output.append("\\t")
                else -> when {
                    character.code < 0x20 -> output.append("\\u%04x".format(character.code))
                    character.isHighSurrogate() -> {
                        require(
                            index + 1 < value.length && value[index + 1].isLowSurrogate(),
                        ) { "canonical JSON forbids isolated UTF-16 surrogates" }
                        output.append(character)
                        index += 1
                        output.append(value[index])
                    }
                    character.isLowSurrogate() -> error(
                        "canonical JSON forbids isolated UTF-16 surrogates",
                    )
                    else -> output.append(character)
                }
            }
            index += 1
        }
        output.append('"')
    }
}

internal fun jsonObject(vararg members: Pair<String, JsonValue>): JsonObject =
    JsonObject(linkedMapOf(*members))

internal fun jsonArray(values: Iterable<JsonValue>): JsonArray = JsonArray(values.toList())

internal fun String.json(): JsonString = JsonString(this)
internal fun Boolean.json(): JsonBoolean = JsonBoolean(this)
internal fun Int.json(): JsonInteger = JsonInteger(toLong())
internal fun Long.json(): JsonInteger = JsonInteger(this)
internal fun String?.nullableJson(): JsonValue = this?.json() ?: JsonNull
internal fun Int?.nullableJson(): JsonValue = this?.json() ?: JsonNull
internal fun Boolean?.nullableJson(): JsonValue = this?.json() ?: JsonNull
