#!/usr/bin/env python3
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
for path in sorted((root/'config/scenarios').glob('*.json')):
    x=json.loads(path.read_text())
    print(f"{path.stem:8} status={x.get('status','?'):10} index={x['index']:18} window={x['start']}..{x['end']} target_questions={x.get('question_target','?')}")
