"""The Firewall → Active Rules tab must never surface nft's raw 'No such file or
directory' when the chain hasn't been created yet (nothing blocked). list_rules must
treat a missing chain as 'no active rules'."""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.firewall_enforcer import _LocalBackend


def _nft_backend():
    # Construct a local backend and force the nft path regardless of host tooling.
    be = _LocalBackend.__new__(_LocalBackend)
    be._use_nft = True
    be._nft_chain_ready = False
    be._NF_TABLE = "iotsentinel"
    be._NF_CHAIN = "forward"
    return be


def test_missing_chain_returns_no_rules():
    be = _nft_backend()
    # _nft maps "No such" to ok=True with the error text as output (its idempotency quirk).
    err = "Error: No such file or directory; list chain inet iotsentinel forward"
    with patch.object(be, "_nft", return_value=(True, err)):
        assert be.list_rules() == [], "missing chain must read as no active rules"


def test_real_rules_are_returned():
    be = _nft_backend()
    chain = ("chain forward {\n"
             "  ip saddr 1.2.3.4 drop\n"
             "  ip saddr 5.6.7.8 drop\n"
             "}")
    with patch.object(be, "_nft", return_value=(True, chain)):
        rules = be.list_rules()
    assert any("1.2.3.4" in r for r in rules) and any("5.6.7.8" in r for r in rules)


def test_hard_error_returns_no_rules():
    be = _nft_backend()
    with patch.object(be, "_nft", return_value=(False, "permission denied")):
        assert be.list_rules() == []
