"""Public benchmark dataset support: NSL-KDD (Tavallaee et al., 2009).

Why NSL-KDD (see ``docs/research-notes/ids-datasets.md``): it is one of the datasets
most used by the IoD-IDS studies surveyed by Ogab et al. (8 studies), it is small
enough to process on a laptop, it removes KDD Cup 99's duplicate records, and it ships
an official train/test split (KDDTrain+ / KDDTest+). Its limitations (old traffic,
not IoD-specific, test-set novel attacks) are reported with the results.

The files must be obtained from the official source (UNB CIC, registration form) and
placed in ``data/raw/nsl-kdd/KDDTrain+.txt`` and ``data/raw/nsl-kdd/KDDTest+.txt``.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from app.models.enums import BENIGN_LABEL

NSL_FEATURES: tuple[str, ...] = (
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
)  # fmt: skip
NSL_CATEGORICAL = ["protocol_type", "service", "flag"]
NSL_NUMERIC = [c for c in NSL_FEATURES if c not in NSL_CATEGORICAL]

#: Standard mapping of NSL-KDD attack names to the four attack categories.
ATTACK_CATEGORY: dict[str, str] = {
    **dict.fromkeys(["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
                     "udpstorm", "processtable", "mailbomb", "worm"], "dos"),
    **dict.fromkeys(["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"], "probe"),
    **dict.fromkeys(["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
                     "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
                     "httptunnel", "sendmail", "named"], "r2l"),
    **dict.fromkeys(["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack", "xterm",
                     "ps"], "u2r"),
}  # fmt: skip

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "data" / "raw" / "nsl-kdd"


class DatasetUnavailableError(FileNotFoundError):
    """The public dataset files are not present locally."""


def available(directory: Path = DEFAULT_DIR) -> bool:
    return (directory / "KDDTrain+.txt").exists() and (directory / "KDDTest+.txt").exists()


def load_file(path: Path) -> pd.DataFrame:
    """Load one NSL-KDD file (41 features, attack name, difficulty) and map labels."""
    df = pd.read_csv(path, header=None, names=[*NSL_FEATURES, "attack", "difficulty"])
    attack = df["attack"].astype(str).str.strip().str.lower()
    unknown = sorted(set(attack) - set(ATTACK_CATEGORY) - {"normal"})
    if unknown:
        raise ValueError(f"unmapped NSL-KDD attack names: {unknown}")
    df["label"] = attack.map(lambda a: BENIGN_LABEL if a == "normal" else ATTACK_CATEGORY[a])
    return df.drop(columns=["difficulty"])


def load(directory: Path = DEFAULT_DIR) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Official split: (KDDTrain+, KDDTest+)."""
    if not available(directory):
        raise DatasetUnavailableError(
            f"NSL-KDD not found in {directory}. Download KDDTrain+.txt and KDDTest+.txt from "
            "https://www.unb.ca/cic/datasets/nsl.html and place them there."
        )
    return load_file(directory / "KDDTrain+.txt"), load_file(directory / "KDDTest+.txt")
