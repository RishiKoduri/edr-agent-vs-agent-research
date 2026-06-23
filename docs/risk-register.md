# Risk Register

| Risk | Likelihood | Impact | Early warning | Mitigation |
|---|---|---|---|---|
| Scope expands across several infrastructure domains | High | High | Domain modeling begins before the baseline experiment works | Freeze one primary environment for Step 1 |
| Agent implementation consumes time needed for experiments | High | High | No end-to-end baseline by August 28 | Prefer simple policies first; gate learning features as stretch work |
| Architecture labels are not behaviorally distinct | Medium | High | Variants differ only in names or configuration wrappers | Specify authority, information flow, and failure modes for each architecture |
| Results reflect action rate rather than coordination | High | High | More agents always means more actions | Include fixed-total-action-rate comparisons |
| Collapse thresholds are selected after seeing main results | Medium | High | Thresholds change during analysis | Calibrate in pilots and freeze before main runs |
| Experiments are not reproducible | Medium | High | Runs lack seeds, manifests, or code revision | Require a run manifest and deterministic seed hierarchy |
| Main experiment matrix is computationally excessive | Medium | Medium | Pilot runtime projects beyond available capacity | Perform power/runtime planning and prioritize core contrasts |
