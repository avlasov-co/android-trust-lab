package org.androidtrustlab.observer.ui

import org.androidtrustlab.observer.probe.AppProbeOutcome
import org.junit.Assert.assertEquals
import org.junit.Test

class ProbePresentationTest {
    @Test
    fun everyOutcomeIsRetainedInOneOrderedCategory() {
        val outcomes = bundle().outcomes.mapIndexed { index, outcome ->
            outcome.copy(status = OutcomeCategory.entries[index % 4].wireStatus)
        }
        val groups = groupOutcomes(outcomes)

        assertEquals(OutcomeCategory.entries, groups.map(OutcomeGroup::category))
        assertEquals(outcomes.map(AppProbeOutcome::probeId).toSet(), groups.flatMap(OutcomeGroup::probeIds).toSet())
        assertEquals(12, groups.sumOf { it.probeIds.size })
    }

    @Test
    fun redactionPreviewExactlyTracksTheArtifactContract() {
        assertEquals(
            listOf(
                RedactionItem.BUILD_FINGERPRINT_HASHED,
                RedactionItem.DIAGNOSTICS_CATEGORIZED,
                RedactionItem.FILE_PATHS_REPLACED,
                RedactionItem.INSTALLER_PACKAGE_CATEGORIZED,
                RedactionItem.MOUNT_FIELDS_ALLOWLISTED,
                RedactionItem.SELINUX_CATEGORIES_REMOVED,
            ),
            redactionItems(),
        )
    }
}
