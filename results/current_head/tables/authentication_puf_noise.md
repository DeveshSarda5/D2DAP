**Authentication success vs software-PUF noise (D2DAP has no error correction)**

|   noise_sigma |   majority_votes |   trials |   success_rate | dominant_failure   |
|--------------:|-----------------:|---------:|---------------:|:-------------------|
|          0    |                1 |       40 |          1     |                    |
|          0    |                5 |       40 |          1     |                    |
|          0    |               15 |       40 |          1     |                    |
|          0.02 |                1 |       40 |          0.5   | secret_mismatch    |
|          0.02 |                5 |       40 |          0.575 | secret_mismatch    |
|          0.02 |               15 |       40 |          0.8   | secret_mismatch    |
|          0.05 |                1 |       40 |          0.125 | secret_mismatch    |
|          0.05 |                5 |       40 |          0.325 | secret_mismatch    |
|          0.05 |               15 |       40 |          0.525 | secret_mismatch    |
|          0.1  |                1 |       40 |          0     | secret_mismatch    |
|          0.1  |                5 |       40 |          0.15  | secret_mismatch    |
|          0.1  |               15 |       40 |          0.1   | secret_mismatch    |
|          0.25 |                1 |       40 |          0     | secret_mismatch    |
|          0.25 |                5 |       40 |          0     | secret_mismatch    |
|          0.25 |               15 |       40 |          0     | secret_mismatch    |
