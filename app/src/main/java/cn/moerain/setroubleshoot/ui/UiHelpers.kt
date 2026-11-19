package cn.moerain.setroubleshoot.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import cn.moerain.setroubleshoot.data.Severity

@Composable
fun severityColor(severity: Severity): Color = when (severity) {
    Severity.INFO -> Color(0xFF2E7D32)
    Severity.WARNING -> Color(0xFFE65100)
    Severity.DANGER -> Color(0xFFC62828)
}

@Composable
fun Badge(text: String, color: Color) {
    Surface(
        color = color.copy(alpha = 0.14f),
        shape = MaterialTheme.shapes.small
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
        )
    }
}

@Composable
fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface
    )
}

const val SAMPLE_LOG: String = """avc: denied { read } for pid=12345 comm="untrusted_app" name="config.xml" dev="dm-0" ino=123456 scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:system_file:s0 tclass=file permissive=0
avc: denied { call } for pid=12345 comm="untrusted_app" scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:activity_service:s0 tclass=binder permissive=0
avc: denied { name_bind } for pid=12345 comm="untrusted_app" src=80 scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0
avc: denied { write } for pid=12345 comm="untrusted_app" path="/data/data/com.example/files/a.txt" dev="dm-0" ino=98765 scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:system_data_file:s0 tclass=file permissive=1"""
