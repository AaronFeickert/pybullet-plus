# PyBullet+

This is a proof-of-concept implementation of the [Bulletproofs+](https://eprint.iacr.org/2020/735) range proving system that supports single-party aggregation and efficient batch verification.
Additionally, it supports recovery of commitment masks in the non-aggregated case, given a common seed used by the prover and verifier.

**This code is experimental and not intended for use in production.**
**It is not written with secure implementation in mind, has not been formally reviewed, and likely contains errors.**

## Requirements

This code requires an active [Python 3 release](https://devguide.python.org/#status-of-python-branches).


## Testing

A test workflow in this repository runs against all active Python 3 release minor versions.

[![Test status](../../actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)

Run the test suite locally using either:
- `python3 -m unittest discover`
- `pytest`
