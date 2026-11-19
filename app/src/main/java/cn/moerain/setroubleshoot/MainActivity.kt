package cn.moerain.setroubleshoot

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import cn.moerain.setroubleshoot.ui.AppRoot
import cn.moerain.setroubleshoot.ui.theme.SETroubleshootTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SETroubleshootTheme {
                AppRoot()
            }
        }
    }
}
