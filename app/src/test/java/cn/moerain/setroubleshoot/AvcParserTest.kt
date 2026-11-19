package cn.moerain.setroubleshoot

import cn.moerain.setroubleshoot.data.AvcParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AvcParserTest {

    @Test
    fun parseDmesgLine() {
        val line = "avc: denied { read write } for pid=1234 comm=\"untrusted_app\" " +
            "name=\"config.xml\" dev=\"dm-0\" ino=123456 " +
            "scontext=u:r:untrusted_app:s0:c512,c768 " +
            "tcontext=u:object_r:system_file:s0 tclass=file permissive=0"

        val event = AvcParser.parseLine(line, "dmesg")

        assertNotNull(event)
        event!!
        assertEquals(listOf("read", "write"), event.perms)
        assertEquals("untrusted_app", event.scontext.type)
        assertEquals("s0:c512,c768", event.scontext.mls)
        assertEquals("system_file", event.tcontext.type)
        assertEquals("file", event.tclass)
        assertEquals("config.xml", event.name)
        assertEquals(false, event.permissive)
        assertEquals("dmesg", event.source)
        assertEquals("untrusted_app", event.subject)
        assertTrue(event.signature.contains("untrusted_app"))
    }

    @Test
    fun parseAuditLineWithPath() {
        val line = "type=AVC msg=audit(1700000000.123:456): avc:  denied  { execute } for  " +
            "pid=13015 comm=\"npviewer.bin\" path=\"/opt/real/nphelix.so\" dev=dm-0 ino=2850912 " +
            "scontext=unconfined_u:unconfined_r:nsplugin_t:s0 " +
            "tcontext=unconfined_u:object_r:usr_t:s0 tclass=file"

        val event = AvcParser.parseLine(line, "audit.log")!!

        assertEquals(listOf("execute"), event.perms)
        assertEquals("/opt/real/nphelix.so", event.path)
        assertEquals("nsplugin_t", event.scontext.type)
        assertEquals("usr_t", event.tcontext.type)
        assertEquals(1700000000123L, event.timestamp)
        assertNotNull(event.eventId)
    }

    @Test
    fun mergeSyscallAndAvcRecords() {
        val text = """
            type=SYSCALL msg=audit(1166017682.366:877): arch=40000003 syscall=196 success=no exit=-13 ppid=23762 pid=23768 comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0 key=(null)
            type=AVC msg=audit(1166017682.366:877): avc:  denied  { execute_no_trans } for  pid=23768 comm="httpd" name="index.html" dev=dm-0 ino=7996439 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file
        """.trimIndent()

        val events = AvcParser.parseLog(text, "test")

        assertEquals(1, events.size)
        val event = events.first()
        assertEquals("/usr/sbin/httpd", event.exe)
        assertEquals("196", event.syscall)
        assertEquals(false, event.success)
        assertEquals("index.html", event.path)
    }

    @Test
    fun mergePathAndCwdAndResolveRelativePath() {
        val text = """
            type=CWD msg=audit(1700000000.123:456): cwd="/data/local/tmp"
            type=PATH msg=audit(1700000000.123:456): item=0 name="a.txt"
            type=AVC msg=audit(1700000000.123:456): avc: denied { read } for pid=1 comm="tool" scontext=u:r:shell:s0 tcontext=u:object_r:shell_data_file:s0 tclass=file
        """.trimIndent()

        val events = AvcParser.parseLog(text, "test")

        assertEquals(1, events.size)
        assertEquals("/data/local/tmp/a.txt", events.first().path)
    }

    @Test
    fun decodeHexEncodedName() {
        val line = "avc: denied { read } for pid=1 comm=\"app\" name=2F646174612F666F6F " +
            "scontext=u:r:untrusted_app:s0 tcontext=u:object_r:system_file:s0 tclass=file"

        val event = AvcParser.parseLine(line)!!

        assertEquals("/data/foo", event.name)
        assertEquals("/data/foo", event.path)
    }

    @Test
    fun ignoreNonAvcLines() {
        assertNull(AvcParser.parseLine("type=SYSCALL msg=audit(1.2:3): syscall=1", "test"))
        assertTrue(AvcParser.parseLog("hello\nworld", "test").isEmpty())
    }

    @Test
    fun permissiveFlagParsed() {
        val line = "avc: denied { write } for pid=1 comm=\"app\" " +
            "scontext=u:r:untrusted_app:s0 tcontext=u:object_r:system_data_file:s0 " +
            "tclass=file permissive=1"

        val event = AvcParser.parseLine(line)!!

        assertEquals(true, event.permissive)
        assertTrue(event.isPermissive)
        assertFalse(event.granted)
    }
}
