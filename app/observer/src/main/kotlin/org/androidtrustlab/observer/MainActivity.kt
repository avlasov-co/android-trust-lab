package org.androidtrustlab.observer

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.ProgressBar
import android.widget.TextView
import java.io.IOException
import org.androidtrustlab.observer.export.AppExportArchive
import org.androidtrustlab.observer.export.SafExportGateway
import org.androidtrustlab.observer.probe.AppProbeBundle
import org.androidtrustlab.observer.probe.PublicAppProbe
import org.androidtrustlab.observer.ui.OutcomeCategory
import org.androidtrustlab.observer.ui.ProbeScreenController
import org.androidtrustlab.observer.ui.ProbeScreenState
import org.androidtrustlab.observer.ui.ProbeSessionStore
import org.androidtrustlab.observer.ui.RedactionItem
import org.androidtrustlab.observer.ui.UiFailure
import org.androidtrustlab.observer.ui.UiNotice
import org.androidtrustlab.observer.ui.groupOutcomes
import org.androidtrustlab.observer.ui.redactionItems

/** Entry point for the deliberately unprivileged, explicitly initiated observer. */
class MainActivity : Activity() {
    private lateinit var controller: ProbeScreenController
    private lateinit var scopeAcknowledgement: CheckBox
    private lateinit var startButton: Button
    private lateinit var progressIndicator: ProgressBar
    private lateinit var collectionStatus: TextView
    private lateinit var resultsSection: View
    private lateinit var resultsText: TextView
    private lateinit var redactionsSection: View
    private lateinit var redactionsText: TextView
    private lateinit var artifactPreviewSection: View
    private lateinit var artifactPreviewText: TextView
    private lateinit var exportButton: Button
    private lateinit var exportStatus: TextView

    private val stateListener: (ProbeScreenState) -> Unit = { state ->
        runOnUiThread { render(state) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()
        markAccessibilityHeadings()

        controller = ProbeSessionStore.getOrCreate { progress, shouldCancel ->
            PublicAppProbe.collect(applicationContext, progress, shouldCancel)
        }
        scopeAcknowledgement.setOnCheckedChangeListener { _, checked ->
            controller.setScopeAcknowledged(checked)
        }
        startButton.setOnClickListener { controller.startProbe() }
        exportButton.setOnClickListener {
            if (controller.requestExport() != null) openExportFolderPicker()
        }
        controller.attach(stateListener)
    }

    override fun onStop() {
        if (!isChangingConfigurations) controller.cancelCollection()
        super.onStop()
    }

    override fun onDestroy() {
        controller.detach(stateListener)
        super.onDestroy()
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != EXPORT_TREE_REQUEST) return
        if (resultCode != RESULT_OK || data?.data == null) {
            controller.cancelExport()
            return
        }
        val destination = data.data ?: return
        val awaiting = controller.state as? ProbeScreenState.AwaitingDestination
        if (awaiting == null) return
        controller.exportTo { bundle ->
            publishExport(destination, awaiting.request.suggestedFilename, bundle)
        }
    }

    private fun bindViews() {
        scopeAcknowledgement = findViewById(R.id.scope_acknowledgement)
        startButton = findViewById(R.id.start_probe_button)
        progressIndicator = findViewById(R.id.progress_indicator)
        collectionStatus = findViewById(R.id.collection_status)
        resultsSection = findViewById(R.id.results_section)
        resultsText = findViewById(R.id.results_text)
        redactionsSection = findViewById(R.id.redactions_section)
        redactionsText = findViewById(R.id.redactions_text)
        artifactPreviewSection = findViewById(R.id.artifact_preview_section)
        artifactPreviewText = findViewById(R.id.artifact_preview_text)
        exportButton = findViewById(R.id.export_button)
        exportStatus = findViewById(R.id.export_status)
    }

    private fun markAccessibilityHeadings() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        listOf(
            R.id.screen_heading,
            R.id.scope_heading,
            R.id.results_heading,
            R.id.limitations_heading,
            R.id.redactions_heading,
            R.id.artifact_preview_heading,
        ).forEach { findViewById<View>(it).isAccessibilityHeading = true }
    }

    private fun render(state: ProbeScreenState) {
        if (scopeAcknowledgement.isChecked != controller.isScopeAcknowledged) {
            scopeAcknowledgement.isChecked = controller.isScopeAcknowledged
        }
        val busy = state is ProbeScreenState.Running ||
            state is ProbeScreenState.AwaitingDestination ||
            state is ProbeScreenState.Exporting
        scopeAcknowledgement.isEnabled = !busy
        startButton.isEnabled = controller.isScopeAcknowledged && !busy
        startButton.setText(
            if (state is ProbeScreenState.Scope) R.string.start_probe else R.string.run_probe_again,
        )

        progressIndicator.visibility = if (state is ProbeScreenState.Running) View.VISIBLE else View.GONE
        if (state is ProbeScreenState.Running) {
            progressIndicator.max = state.total
            progressIndicator.progress = state.completed
            progressIndicator.contentDescription = getString(
                R.string.progress_description,
                state.completed,
                state.total,
            )
            collectionStatus.text = getString(R.string.status_running, state.completed, state.total)
        }

        val bundle = when (state) {
            is ProbeScreenState.Ready -> state.bundle
            is ProbeScreenState.AwaitingDestination -> state.bundle
            is ProbeScreenState.Exporting -> state.bundle
            else -> null
        }
        renderReview(bundle, state is ProbeScreenState.Ready)

        when (state) {
            ProbeScreenState.Scope -> collectionStatus.setText(R.string.status_not_started)
            is ProbeScreenState.Running -> Unit
            is ProbeScreenState.Ready -> {
                collectionStatus.setText(
                    if (state.bundle.metadata.completionStatus == "complete") {
                        R.string.status_complete
                    } else {
                        R.string.status_partial
                    },
                )
                renderExportNotice(state.notice)
            }
            is ProbeScreenState.AwaitingDestination -> showExportStatus(R.string.export_waiting)
            is ProbeScreenState.Exporting -> showExportStatus(R.string.export_running)
            is ProbeScreenState.Failed -> {
                collectionStatus.setText(
                    if (state.failure == UiFailure.PROBE_CANCELLED) {
                        R.string.status_cancelled
                    } else {
                        R.string.status_failed
                    },
                )
                hideExportStatus()
            }
        }
    }

    private fun renderReview(bundle: AppProbeBundle?, canExport: Boolean) {
        val visibility = if (bundle == null) View.GONE else View.VISIBLE
        resultsSection.visibility = visibility
        redactionsSection.visibility = visibility
        artifactPreviewSection.visibility = visibility
        exportButton.visibility = visibility
        exportButton.isEnabled = bundle != null && canExport
        if (bundle == null) {
            hideExportStatus()
            return
        }
        resultsText.text = formatOutcomes(bundle)
        redactionsText.text = formatRedactions()
        artifactPreviewText.text = bundle.artifactBytes.toString(Charsets.UTF_8)
    }

    private fun formatOutcomes(bundle: AppProbeBundle): String = buildString {
        append(
            getString(
                R.string.results_metadata,
                getString(
                    if (bundle.metadata.completionStatus == "complete") {
                        R.string.completion_complete
                    } else {
                        R.string.completion_partial
                    },
                ),
                bundle.metadata.appVersion,
                bundle.metadata.appProbeSchemaVersion,
            ),
        )
        groupOutcomes(bundle.outcomes).forEach { group ->
            append('\n')
            append(getString(categoryLabel(group.category)))
            append(':')
            if (group.probeIds.isEmpty()) {
                append(' ')
                append(getString(R.string.category_none))
            } else {
                group.probeIds.forEach { probeId ->
                    append("\n• ")
                    append(getString(probeLabel(probeId)))
                }
            }
        }
    }

    private fun formatRedactions(): String = buildString {
        append(getString(R.string.redactions_intro))
        redactionItems().forEach { item ->
            append("\n• ")
            append(getString(redactionLabel(item)))
        }
    }

    private fun renderExportNotice(notice: UiNotice) {
        when (notice) {
            UiNotice.NONE -> hideExportStatus()
            UiNotice.EXPORT_COMPLETE -> showExportStatus(R.string.export_complete)
            UiNotice.EXPORT_CANCELLED -> showExportStatus(R.string.export_cancelled)
            UiNotice.EXPORT_FAILED -> showExportStatus(R.string.export_failed)
        }
    }

    private fun showExportStatus(message: Int) {
        exportStatus.visibility = View.VISIBLE
        exportStatus.setText(message)
    }

    private fun hideExportStatus() {
        exportStatus.visibility = View.GONE
        exportStatus.text = ""
    }

    @Suppress("DEPRECATION")
    private fun openExportFolderPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            putExtra(Intent.EXTRA_LOCAL_ONLY, true)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
        try {
            startActivityForResult(intent, EXPORT_TREE_REQUEST)
        } catch (_: ActivityNotFoundException) {
            controller.failExportSelection()
        } catch (_: SecurityException) {
            controller.failExportSelection()
        }
    }

    private fun publishExport(destination: Uri, filename: String, bundle: AppProbeBundle) {
        if (!DocumentsContract.isTreeUri(destination)) throw IOException()
        val archive = AppExportArchive.build(bundle)
        SafExportGateway.publish(applicationContext, destination, filename, archive)
    }

    private fun categoryLabel(category: OutcomeCategory): Int = when (category) {
        OutcomeCategory.OBSERVED -> R.string.category_observed
        OutcomeCategory.INACCESSIBLE -> R.string.category_inaccessible
        OutcomeCategory.UNSUPPORTED -> R.string.category_unsupported
        OutcomeCategory.ERROR -> R.string.category_error
    }

    private fun redactionLabel(item: RedactionItem): Int = when (item) {
        RedactionItem.BUILD_FINGERPRINT_HASHED -> R.string.redaction_build_fingerprint
        RedactionItem.DIAGNOSTICS_CATEGORIZED -> R.string.redaction_diagnostics
        RedactionItem.FILE_PATHS_REPLACED -> R.string.redaction_file_paths
        RedactionItem.INSTALLER_PACKAGE_CATEGORIZED -> R.string.redaction_installer
        RedactionItem.MOUNT_FIELDS_ALLOWLISTED -> R.string.redaction_mounts
        RedactionItem.SELINUX_CATEGORIES_REMOVED -> R.string.redaction_selinux
    }

    private fun probeLabel(probeId: String): Int = when (probeId) {
        "build_version" -> R.string.probe_build_version
        "app_identity" -> R.string.probe_app_identity
        "install_source" -> R.string.probe_install_source
        "selinux_self_context" -> R.string.probe_selinux_context
        "file_system_shell" -> R.string.probe_system_shell
        "file_system_su" -> R.string.probe_system_su
        "file_system_xbin_su" -> R.string.probe_system_xbin_su
        "file_vendor_bin_su" -> R.string.probe_vendor_su
        "file_sbin_su" -> R.string.probe_sbin_su
        "proc_self_status" -> R.string.probe_proc_status
        "proc_self_mountinfo" -> R.string.probe_mount_info
        "emulator_indicators" -> R.string.probe_emulator_indicators
        else -> error("Unmapped probe contract identifier")
    }

    private companion object {
        const val EXPORT_TREE_REQUEST = 3301
    }
}
