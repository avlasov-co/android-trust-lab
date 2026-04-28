# Experiment Methodology

Every experiment must be reproducible and explicit. The purpose is measurement, not informal device judgment.

## Required fields

- experiment_id
- target_type
- target_config
- preconditions
- controlled_change
- expected_state
- collection_steps
- artifacts_produced
- actual_state
- diff_summary
- limitations
- status

## Evaluation rule

Expected state and actual state must be separate. If the target behaves differently than expected, record the difference explicitly instead of rewriting the expected state.

## Artifacts

Each experiment should produce:

- raw artifact
- normalized report
- validation result
- optional diff
- summary table row

## Confidence

Confidence must be lower for emulator claims touching hardware-backed trust, bootloader, TEE, or vendor-specific behavior.
