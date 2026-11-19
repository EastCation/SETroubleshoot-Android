package cn.moerain.setroubleshoot.data

import java.util.Locale

/**
 * AVC 文本解析器。
 *
 * 支持内核 dmesg 与 audit/logcat 两种常见格式：
 *
 * avc: denied { read write } for pid=1234 comm="app" name="foo" dev="dm-0" ino=10 \
 *     scontext=u:r:untrusted_app:s0 tcontext=u:object_r:system_file:s0 tclass=file permissive=0
 *
 * type=AVC msg=audit(1700000000.123:456): avc: denied { read } for pid=... \
 *     scontext=... tcontext=... tclass=file
 *
 * 同时会把同一 audit 事件中的 SYSCALL / PATH / CWD / AVC_PATH 记录合并到 AVC 上，
 * 对应 setroubleshoot 中的 AuditRecordReceiver / AuditEvent 组装逻辑。
 */
object AvcParser {

    private val avcRegex = Regex(
        """\bavc:\s+(denied|granted)\s+\{([^}]*)\}\s+for\s+(.*)""",
        RegexOption.IGNORE_CASE
    )
    private val auditIdRegex = Regex("""audit\((\d+)\.(\d+):(\d+)\)""")
    private val kvRegex = Regex("""([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|[^\s]+)""")
    private val typeRegex = Regex("""\btype=([A-Za-z0-9_]+)""")
    private val hexRegex = Regex("""^[0-9A-Fa-f]+$""")
    private val whitespaceRegex = Regex("""\s+""")

    private val hexEncodedKeys = setOf(
        "name", "path", "comm", "exe", "cwd", "cmd", "acct", "dir", "msg", "old", "ocomm"
    )

    private const val MAX_EVENTS = 8000

    fun parseLog(text: String, source: String = "unknown"): List<AvcEvent> {
        if (text.isBlank()) return emptyList()
        val lines = text.lines()
        val events = ArrayList<AvcEvent>()
        val indexById = HashMap<String, Int>()
        val seenRaw = HashSet<String>()

        // 第一遍：解析所有 AVC 记录。
        for (line in lines) {
            if (events.size >= MAX_EVENTS) break
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            if (!trimmed.contains("avc:", ignoreCase = true)) continue
            if (!seenRaw.add(trimmed)) continue

            val event = parseLine(trimmed, source) ?: continue
            val id = event.eventId
            if (id != null) {
                // 同一事件 id 可能有多条 AVC（不同 record），以最后一条为主。
                indexById[id] = events.size
            }
            events.add(event)
        }

        if (events.isEmpty()) return emptyList()

        // 第二遍：合并同一 audit 事件的附带记录（顺序无关）。
        for (line in lines) {
            if (!line.contains("audit(", ignoreCase = true)) continue
            val idMatch = auditIdRegex.find(line) ?: continue
            val id = idMatch.value
            val index = indexById[id] ?: continue
            if (line.contains("avc:", ignoreCase = true)) continue
            events[index] = mergeAuxLine(events[index], line)
        }

        return events.map { resolvePath(it) }
    }

    fun parseLine(line: String, source: String = "unknown"): AvcEvent? {
        val avc = avcRegex.find(line) ?: return null
        val granted = avc.groupValues[1].equals("granted", ignoreCase = true)
        val perms = avc.groupValues[2]
            .trim()
            .split(whitespaceRegex)
            .filter { it.isNotBlank() }
        val fields = parseFields(avc.groupValues[3])

        val idMatch = auditIdRegex.find(line)
        val eventId = idMatch?.value
        val timestamp = idMatch?.let { m ->
            val seconds = m.groupValues[1].toLongOrNull() ?: 0L
            val millis = m.groupValues[2].toLongOrNull() ?: 0L
            seconds * 1000L + millis
        }

        val scontextRaw = fields["scontext"]
        val tcontextRaw = fields["tcontext"]
        if (scontextRaw.isNullOrBlank() || tcontextRaw.isNullOrBlank()) return null

        val event = AvcEvent(
            raw = line,
            timestamp = timestamp,
            eventId = eventId,
            pid = fields["pid"]?.toIntOrNull(),
            comm = fields["comm"]?.ifBlank { null },
            exe = fields["exe"]?.ifBlank { null },
            name = fields["name"]?.ifBlank { null },
            path = fields["path"]?.ifBlank { null },
            cwd = fields["cwd"]?.ifBlank { null },
            dev = fields["dev"]?.ifBlank { null },
            ino = fields["ino"]?.toLongOrNull(),
            port = (fields["dest"] ?: fields["src"])?.ifBlank { null },
            scontext = SeContext.parse(scontextRaw),
            tcontext = SeContext.parse(tcontextRaw),
            tclass = fields["tclass"]?.ifBlank { "unknown" } ?: "unknown",
            perms = if (perms.isEmpty()) listOf("unknown") else perms,
            permissive = fields["permissive"]?.let { it == "1" || it.equals("true", true) },
            granted = granted,
            syscall = fields["syscall"],
            success = fields["success"]?.let { it.equals("yes", true) || it == "1" },
            source = source
        )
        return resolvePath(event)
    }

    private fun mergeAuxLine(event: AvcEvent, line: String): AvcEvent {
        val fields = parseFields(line)
        val type = typeRegex.find(line)?.groupValues?.getOrNull(1)?.uppercase(Locale.US) ?: ""
        var merged = event

        when (type) {
            "SYSCALL" -> merged = merged.copy(
                comm = fields["comm"]?.ifBlank { null } ?: merged.comm,
                exe = fields["exe"]?.ifBlank { null } ?: merged.exe,
                syscall = fields["syscall"] ?: merged.syscall,
                success = fields["success"]?.let { it.equals("yes", true) || it == "1" } ?: merged.success
            )

            "CWD" -> merged = merged.copy(cwd = fields["cwd"] ?: merged.cwd)

            "PATH", "AVC_PATH" -> {
                val newPath = fields["path"] ?: fields["name"]
                if (!newPath.isNullOrBlank()) {
                    merged = if (newPath.startsWith("/")) {
                        merged.copy(path = newPath)
                    } else {
                        merged.copy(name = merged.name ?: newPath, path = merged.path ?: newPath)
                    }
                }
            }
        }

        return merged
    }

    private fun resolvePath(event: AvcEvent): AvcEvent {
        val rawPath = event.path ?: event.name
        if (rawPath.isNullOrBlank()) return event
        if (rawPath.startsWith("/")) {
            return if (event.path == null) event.copy(path = rawPath) else event
        }
        val cwd = event.cwd
        if (cwd.isNullOrBlank() || !cwd.startsWith("/")) {
            return if (event.path == null) event.copy(path = rawPath) else event
        }
        return if (event.path == null || !event.path.startsWith("/")) {
            event.copy(path = joinPath(cwd, rawPath))
        } else {
            event
        }
    }

    private fun joinPath(base: String, relative: String): String {
        val parts = ArrayDeque<String>()
        (base.trimEnd('/') + "/" + relative).split('/').forEach { part ->
            when (part) {
                "", "." -> Unit
                ".." -> if (parts.isNotEmpty()) parts.removeLast()
                else -> parts.addLast(part)
            }
        }
        return "/" + parts.joinToString("/")
    }

    private fun parseFields(text: String): Map<String, String> {
        val fields = LinkedHashMap<String, String>()
        for (match in kvRegex.findAll(text)) {
            val key = match.groupValues[1]
            val value = decodeValue(key, match.groupValues[2])
            fields[key] = value
        }
        return fields
    }

    private fun decodeValue(key: String, rawValue: String): String {
        val quoted = rawValue.length >= 2 && rawValue.startsWith('"') && rawValue.endsWith('"')
        val value = if (quoted) rawValue.substring(1, rawValue.length - 1) else rawValue
        if (quoted) return value
        if (key !in hexEncodedKeys) return value
        if (value.length < 2 || value.length % 2 != 0 || !hexRegex.matches(value)) return value
        return runCatching {
            value.chunked(2)
                .map { it.toInt(16).toChar() }
                .joinToString("")
        }.getOrDefault(value)
    }
}
