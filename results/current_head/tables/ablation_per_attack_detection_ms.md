**Ablation study of the adaptive framework: per-attack detection_ms**

| kind                 |   adaptive |   no_trust |    no_ml |   no_policy |   no_attribution |
|:---------------------|-----------:|-----------:|---------:|------------:|-----------------:|
| abnormal             |    1000    |       1000 |  2333.33 |     1000    |             1000 |
| dos                  |    5000    |       1000 |  4000    |     5000    |             1000 |
| flooding             |    1000    |       1000 |  2000    |     1000    |             1000 |
| impersonation        |    5333.33 |       1000 |  9000    |     5333.33 |             1000 |
| privilege_escalation |    1000    |       1000 |  1000    |     1000    |             1000 |
| replay               |    6500    |       1000 |  6500    |     6500    |             1000 |
| spoofing             |    6333.33 |       1000 | 11333.3  |     6333.33 |             1000 |
| tampering            |   11500    |       1000 |   nan    |    11500    |             1000 |
| unauthorized_access  |    1000    |       1000 |  1000    |     1000    |             1000 |
