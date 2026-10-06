"""LITERATURE values transcribed from the D2DAP paper (Parai et al., IEEE TVT 2026).

These numbers are copied from the paper's tables. They were obtained by the authors on a
Raspberry Pi 3 / Intel laptop and are reported in CPU cycles or bits. They are NOT our
measurements and must always be labelled "Literature" when shown next to ours.
"""

from __future__ import annotations

SOURCE = "Parai et al., D2DAP, IEEE TVT 2026 (DOI 10.1109/TVT.2026.3674144)"

#: Table VII: total communication cost of D2DAP (bits, 2 rounds).
#: Note: 2008 at the 256-bit level does not follow the 1024/1536 progression (2048 would);
#: it is reproduced as printed.
COMM_COST_BITS = {128: 1024, 192: 1536, 256: 2008}
COMM_ROUNDS = 2

#: Table VIII: CPU cycles per operation on the drone platform (Raspberry Pi 3, column D_j).
OP_CYCLES_DRONE: dict[int, dict[str, float]] = {
    128: {
        "point_mul": 23.54e6, "point_add": 88.89e4, "exp": 22.21e6, "hash": 92.93e2,
        "sym": 31.83e5, "puf": 64.30e5, "ss_gen": 27.74e4, "ss_rec": 71.39e4, "rand": 45.49e3,
    },
    192: {
        "point_mul": 37.26e6, "point_add": 13.53e5, "exp": 88.49e6, "hash": 10.80e3,
        "sym": 37.50e5, "puf": 95.13e5, "ss_gen": 28.07e4, "ss_rec": 10.83e5, "rand": 54.68e3,
    },
    256: {
        "point_mul": 53.43e6, "point_add": 20.06e5, "exp": 28.07e7, "hash": 11.08e3,
        "sym": 42.14e5, "puf": 13.57e6, "ss_gen": 38.79e4, "ss_rec": 14.56e5, "rand": 63.94e3,
    },
}  # fmt: skip

#: Table IX: total computation cost of D2DAP per drone (CPU cycles).
COMP_COST_PER_DRONE_CYCLES = {128: 108_654_520, 192: 168_637_713, 256: 239_291_352}
COMP_COST_TOTAL_CYCLES = {128: 217_309_040, 192: 337_275_426, 256: 478_582_704}

#: Raspberry Pi 3 clock used for the drone platform in the paper (Table XI: 1200 MHz).
RPI_CLOCK_HZ = 1.2e9
