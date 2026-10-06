**Ablation study of the adaptive framework: per-attack mitigation_rate**

| kind                 |   adaptive |   no_trust |   no_ml |   no_policy |   no_attribution |   d2dap |
|:---------------------|-----------:|-----------:|--------:|------------:|-----------------:|--------:|
| abnormal             |      0.895 |      0.976 |   0.643 |       0.076 |            0.897 |   0.073 |
| dos                  |      1     |      1     |   1     |       1     |            1     |   1     |
| flooding             |      0.858 |      0.971 |   0.728 |       0.126 |            0.876 |   0.127 |
| impersonation        |      1     |      1     |   1     |       1     |            1     |   1     |
| privilege_escalation |      0.928 |      0.962 |   0.9   |       0.015 |            0.928 |   0.014 |
| replay               |      0.913 |      0.964 |   0.914 |       0.913 |            0.968 |   0.921 |
| spoofing             |      1     |      1     |   1     |       1     |            1     |   1     |
| tampering            |      1     |      1     |   1     |       1     |            1     |   1     |
| unauthorized_access  |      1     |      1     |   1     |       1     |            1     |   1     |
