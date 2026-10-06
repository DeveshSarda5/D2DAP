**Sensitivity of the adaptive framework to thresholds and trust weights**

| setting         |   detection_rate |   detection_ms_median |   mitigation_rate |   fpr_flag_rate |   disruption_rate |   collateral_rate |
|:----------------|-----------------:|----------------------:|------------------:|----------------:|------------------:|------------------:|
| default         |                1 |                  1000 |            0.9188 |          0.0222 |            0      |            0      |
| bands -0.1      |                1 |                  1500 |            0.8871 |          0.0018 |            0      |            0      |
| bands +0.1      |                1 |                  1000 |            0.944  |          0.1575 |            0.0018 |            0.0002 |
| w_ml_attack 1.5 |                1 |                  1000 |            0.9074 |          0.0064 |            0      |            0      |
| w_ml_attack 4.5 |                1 |                  1000 |            0.9412 |          0.0302 |            0      |            0      |
| decay 0.75      |                1 |                  1000 |            0.931  |          0.0158 |            0      |            0      |
| decay 0.95      |                1 |                  1000 |            0.9084 |          0.0274 |            0      |            0      |
