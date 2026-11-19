package cn.moerain.setroubleshoot

import cn.moerain.setroubleshoot.data.AvcAnalyzer
import cn.moerain.setroubleshoot.data.AvcEvent
import cn.moerain.setroubleshoot.data.SeContext
import cn.moerain.setroubleshoot.data.SelinuxStatus
import cn.moerain.setroubleshoot.data.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AvcAnalyzerTest {

    private val enforcingStatus = SelinuxStatus(
        root = true,
        selinuxEnabled = true,
        enforcing = true,
        enforceKnown = true,
        modeText = "Enforcing",
        collectedAt = 1L
    )

    private fun makeEvent(
        sourceType: String = "untrusted_app",
        targetType: String = "system_file",
        tclass: String = "file",
        perms: List<String> = listOf("read"),
        path: String? = null,
        name: String? = null,
        permissive: Boolean? = null,
        port: String? = null,
        comm: String = "app"
    ): AvcEvent = AvcEvent(
        raw = "raw",
        comm = comm,
        name = name,
        path = path,
        port = port,
        scontext = SeContext("u", "r", sourceType, "s0"),
        tcontext = SeContext("u", "object_r", targetType, "s0"),
        tclass = tclass,
        perms = perms,
        permissive = permissive
    )

    @Test
    fun permissiveEventIsNotTreatedAsDenial() {
        val event = makeEvent(permissive = true, path = "/data/foo")
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("permissive", analysis.ruleId)
        assertEquals(Severity.INFO, analysis.severity)
        assertTrue(analysis.description.contains("permissive", ignoreCase = true))
    }

    @Test
    fun systemFileAccessFromAppUsesSystemPartitionRule() {
        val event = makeEvent(
            path = "/system/etc/permissions/platform.xml",
            targetType = "system_file",
            perms = listOf("read")
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("system_partition", analysis.ruleId)
        assertEquals(Severity.WARNING, analysis.severity)
        assertTrue(analysis.suggestions.any { it.title.contains("应用私有") })
    }

    @Test
    fun unlabeledTargetSuggestsRestorecon() {
        val event = makeEvent(
            path = "/data/local/tmp/tool",
            targetType = "unlabeled",
            perms = listOf("execute")
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("unlabeled_file", analysis.ruleId)
        assertTrue(analysis.suggestions.any { it.command?.contains("restorecon") == true })
    }

    @Test
    fun binderDenialUsesBinderRule() {
        val event = makeEvent(
            targetType = "activity_service",
            tclass = "binder",
            perms = listOf("call")
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("binder", analysis.ruleId)
        assertTrue(analysis.description.contains("Binder"))
    }

    @Test
    fun capabilityDenialExplainsCapability() {
        val event = makeEvent(
            targetType = "self",
            tclass = "capability",
            perms = listOf("net_admin")
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("capability", analysis.ruleId)
        assertTrue(analysis.description.contains("net_admin"))
    }

    @Test
    fun privilegedPortDenialIsDetected() {
        val event = makeEvent(
            targetType = "http_port_t",
            tclass = "tcp_socket",
            perms = listOf("name_bind"),
            port = "80"
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals("network", analysis.ruleId)
        assertTrue(analysis.description.contains("特权端口"))
        assertTrue(analysis.suggestions.any { it.title == "改用非特权端口" })
    }

    @Test
    fun unknownEnforceModeIsNotTreatedAsPermissive() {
        val event = makeEvent(
            path = "/system/etc/permissions/platform.xml",
            targetType = "system_file",
            perms = listOf("read")
        )
        val unknownStatus = SelinuxStatus(
            root = false,
            selinuxEnabled = true,
            enforcing = false,
            enforceKnown = false,
            modeText = "状态未知"
        )
        val analysis = AvcAnalyzer.analyze(event, unknownStatus)

        assertTrue(analysis.ruleId != "permissive")
        assertEquals(Severity.WARNING, analysis.severity)
    }

    @Test
    fun policyRuleIsGeneratedAndGenericSuggestionsPresent() {
        val event = makeEvent(
            targetType = "system_data_file",
            tclass = "file",
            perms = listOf("read", "write")
        )
        val analysis = AvcAnalyzer.analyze(event, enforcingStatus)

        assertEquals(
            "allow untrusted_app system_data_file:file { read write };",
            analysis.policyRule
        )
        assertTrue(analysis.suggestions.any { it.command?.contains("magiskpolicy") == true })
        assertTrue(analysis.suggestions.any { it.command?.contains("setenforce") == true })
    }
}
