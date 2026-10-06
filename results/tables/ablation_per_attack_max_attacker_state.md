**Ablation study of the adaptive framework: per-attack max_attacker_state**

| kind                 |   adaptive |   no_trust |   no_ml |   no_policy |   no_attribution |   d2dap |
|:---------------------|-----------:|-----------:|--------:|------------:|-----------------:|--------:|
| abnormal             |      4     |          4 |   3     |       4     |            4     |       0 |
| dos                  |      1     |          4 |   3.333 |       1     |            4     |       0 |
| flooding             |      3.667 |          4 |   3.667 |       4     |            4     |       0 |
| impersonation        |      1     |          4 |   1     |       1     |            4     |       0 |
| privilege_escalation |      4     |          4 |   4     |       4     |            4     |       0 |
| replay               |      0.667 |          4 |   0.667 |       0.667 |            3.333 |       0 |
| spoofing             |      1     |          4 |   1     |       1     |            4     |       0 |
| tampering            |      0.667 |          4 |   0     |       0.667 |            3.667 |       0 |
| unauthorized_access  |      4     |          4 |   4     |       4     |            4     |       0 |
