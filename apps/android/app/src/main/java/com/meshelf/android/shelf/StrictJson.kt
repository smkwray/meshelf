package com.meshelf.android.shelf

/**
 * Minimal strict JSON reader for bounded native results. Android's org.json silently keeps the last
 * of duplicate member names and is a stub in JVM unit tests, so the fail-closed decoder uses this.
 * Objects become [LinkedHashMap], arrays [List], integers [Long], other numbers [Double].
 */
object StrictJson {
    class Malformed(message: String) : Exception(message)

    const val MAX_INPUT_CHARS = 2 * 1024 * 1024
    private const val MAX_DEPTH = 32

    fun parse(text: String): Any? {
        if (text.length > MAX_INPUT_CHARS) throw Malformed("input exceeds bound")
        val reader = Reader(text)
        reader.skipWhitespace()
        val value = reader.value(0)
        reader.skipWhitespace()
        if (!reader.atEnd()) throw Malformed("trailing content at ${reader.pos}")
        return value
    }

    private class Reader(val s: String) {
        var pos = 0

        fun atEnd() = pos >= s.length

        fun skipWhitespace() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw Malformed("nesting too deep")
            if (atEnd()) throw Malformed("unexpected end")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') number() else throw Malformed("unexpected '$c' at $pos")
            }
        }

        private fun literal(word: String, result: Any?): Any? {
            if (!s.startsWith(word, pos)) throw Malformed("bad literal at $pos")
            pos += word.length
            return result
        }

        private fun obj(depth: Int): Map<String, Any?> {
            pos++
            val out = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (!atEnd() && s[pos] == '}') { pos++; return out }
            while (true) {
                skipWhitespace()
                if (atEnd() || s[pos] != '"') throw Malformed("expected member name at $pos")
                val name = string()
                if (out.containsKey(name)) throw Malformed("duplicate member '$name'")
                skipWhitespace()
                expect(':')
                skipWhitespace()
                out[name] = value(depth + 1)
                skipWhitespace()
                if (atEnd()) throw Malformed("unterminated object")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> throw Malformed("expected ',' or '}' at $pos")
                }
            }
        }

        private fun array(depth: Int): List<Any?> {
            pos++
            val out = ArrayList<Any?>()
            skipWhitespace()
            if (!atEnd() && s[pos] == ']') { pos++; return out }
            while (true) {
                skipWhitespace()
                out += value(depth + 1)
                skipWhitespace()
                if (atEnd()) throw Malformed("unterminated array")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> throw Malformed("expected ',' or ']' at $pos")
                }
            }
        }

        private fun expect(c: Char) {
            if (atEnd() || s[pos] != c) throw Malformed("expected '$c' at $pos")
            pos++
        }

        private fun string(): String {
            pos++
            val out = StringBuilder()
            while (true) {
                if (atEnd()) throw Malformed("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (atEnd()) throw Malformed("bad escape")
                        when (val e = s[pos++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) throw Malformed("bad unicode escape")
                                val code = s.substring(pos, pos + 4).toIntOrNull(16)
                                    ?: throw Malformed("bad unicode escape")
                                out.append(code.toChar())
                                pos += 4
                            }
                            else -> throw Malformed("bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> throw Malformed("control character in string")
                    else -> out.append(c)
                }
            }
        }

        private fun number(): Any {
            val start = pos
            if (s[pos] == '-') pos++
            if (atEnd()) throw Malformed("bad number")
            if (s[pos] == '0') pos++ else if (s[pos] in '1'..'9') {
                while (!atEnd() && s[pos] in '0'..'9') pos++
            } else throw Malformed("bad number")
            var integral = true
            if (!atEnd() && s[pos] == '.') {
                integral = false
                pos++
                val digits = pos
                while (!atEnd() && s[pos] in '0'..'9') pos++
                if (pos == digits) throw Malformed("bad fraction")
            }
            if (!atEnd() && (s[pos] == 'e' || s[pos] == 'E')) {
                integral = false
                pos++
                if (!atEnd() && (s[pos] == '+' || s[pos] == '-')) pos++
                val digits = pos
                while (!atEnd() && s[pos] in '0'..'9') pos++
                if (pos == digits) throw Malformed("bad exponent")
            }
            val raw = s.substring(start, pos)
            return if (integral) raw.toLongOrNull() ?: throw Malformed("integer out of range")
            else raw.toDouble()
        }
    }
}
