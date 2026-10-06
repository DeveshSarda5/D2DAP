**Table 5: per-attack performance of the operational model (xgboost)**

| class                |   precision |   recall |     f1 |   support |
|:---------------------|------------:|---------:|-------:|----------:|
| abnormal             |      0.9565 |   0.6804 | 0.7952 |        97 |
| benign               |      0.9986 |   0.9992 | 0.9989 |     17439 |
| dos                  |      0.9824 |   0.9871 | 0.9847 |       621 |
| flooding             |      0.8426 |   0.9785 | 0.9055 |        93 |
| impersonation        |      0.9806 |   0.9806 | 0.9806 |       103 |
| privilege_escalation |      1      |   1      | 1      |        90 |
| replay               |      0.9452 |   0.8519 | 0.8961 |        81 |
| spoofing             |      0.8837 |   0.95   | 0.9157 |        80 |
| tampering            |      0.9589 |   1      | 0.979  |        70 |
| unauthorized_access  |      0.9886 |   0.9775 | 0.9831 |        89 |
