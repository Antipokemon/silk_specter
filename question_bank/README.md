# Canonical question banks

This directory is the only committed question/answer/hint source.

| Track | Questions | Hints | Status |
|---|---:|---:|---|
| Easy | 180 | 360 | validated |
| Medium | 170 | 510 | runtime validation pending |
| Hard | 150 | 450 | runtime validation pending |

Each track contains:

- `questions.csv` — CTF runtime fields plus subject and instructor reference metadata
- `answers.csv` — answer and answer type
- `hints.csv` — progressive hints
- `STATUS.md` — track-specific status

The registration/import app should consume these files directly. Do not maintain parallel copies in `instructor/` or `participant/`.
