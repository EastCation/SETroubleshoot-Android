package cn.moerain.setroubleshoot.ui

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import cn.moerain.setroubleshoot.AppController
import cn.moerain.setroubleshoot.data.AvcAlert
import cn.moerain.setroubleshoot.data.Severity

@Composable
fun AppRoot() {
    val controller = remember { AppController() }
    var selectedAlert by remember { mutableStateOf<AvcAlert?>(null) }
    var showPaste by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf<Severity?>(null) }
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        controller.bootstrap()
    }

    LaunchedEffect(controller.message) {
        val text = controller.message
        if (text != null) {
            controller.consumeMessage()
            snackbar.showSnackbar(text)
        }
    }

    val currentAlert = selectedAlert
    when {
        showPaste -> PasteLogScreen(
            controller = controller,
            snackbarHost = snackbar,
            onBack = { showPaste = false }
        )

        currentAlert != null -> AlertDetailScreen(
            controller = controller,
            alert = currentAlert,
            snackbarHost = snackbar,
            onBack = { selectedAlert = null }
        )

        else -> MainScreen(
            controller = controller,
            snackbarHost = snackbar,
            filter = filter,
            onFilterChange = { filter = it },
            onOpenAlert = { selectedAlert = it },
            onOpenPaste = { showPaste = true }
        )
    }
}
