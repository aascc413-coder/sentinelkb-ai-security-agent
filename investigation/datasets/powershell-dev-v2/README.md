# PowerShell development dataset v2

M10b development dataset: 12 synthetic cases in 7 indivisible families. All cases use `split=dev`; this directory contains no blind test set and supports no statistical advantage claim.

The original five seed cases are reproduced from `scripts/build_seed_dataset.py`. Cases C6–C12 add:

- grounded browser credential collection and upload;
- approved Office reporting with complete zero-network coverage;
- matched and mismatched remote administration;
- a second indistinguishable malicious/benign telemetry-gap pair;
- directly observed unauthorized file encryption.

Expected evidence-aware outcomes under the frozen engineering model are:

| Case | Expected outcome |
|---|---|
| C1 | TP |
| C2 | FP |
| C3 | Suspicious |
| C4–C5 | Abstain |
| C6 | TP |
| C7–C8 | FP |
| C9 | Suspicious |
| C10–C11 | Abstain |
| C12 | TP |

Authoring and audit commands, from `investigation/`:

```powershell
.\.venv\Scripts\python.exe scripts\build_dev_dataset.py
.\.venv\Scripts\python.exe scripts\dataset_split_audit.py --dataset datasets\powershell-dev-v2
```

The builder also freezes `evaluation/annotations/powershell-dev-v2.json`. Runtime receives only the mapped PublicCase and tool environment; oracle, family, split and evaluation annotations remain outside model inputs.
