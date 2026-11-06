"""
`redhand bench`: measurement before features (Phase 4 M1, docs/plans/phase4-plan.md).

A labelled corpus (benign and malicious samples per category, English and Malay) is run through the detectors
RedHand actually ships, and the result is reported as detection and false-alarm rates with confidence intervals.
The coverage table in docs/security/coverage-matrix.md is generated from that run, never written by hand.
"""
