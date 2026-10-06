**Normal traffic profile (10 drones, 120 s, simulation)**

| protocol      |   packets |   rate_pps |   mean_size_b |   std_size_b |   throughput_kbps |   delivery_ratio |
|:--------------|----------:|-----------:|--------------:|-------------:|------------------:|-----------------:|
| auth_request  |        23 |      0.192 |       152     |        0     |             0.233 |            1     |
| auth_response |        23 |      0.192 |       152     |        0     |             0.233 |            1     |
| command       |        65 |      0.542 |        79.846 |        8.601 |             0.346 |            0.985 |
| heartbeat     |      6684 |     55.7   |        39.592 |        4.051 |            17.642 |            0.981 |
| rl_broadcast  |       124 |      1.033 |        32     |        0     |             0.265 |            0.992 |
| telemetry     |      5653 |     47.108 |       119.491 |       12.249 |            45.032 |            0.985 |
| video         |      3999 |     33.325 |      1101.93  |      110.555 |           293.775 |            0.988 |
