"""Runtime collector parsing tests."""

from linux_hardening_advisor.runtime.listening_ports import _parse_one_line


def test_parse_ss_line_tcp_listen():
    line = "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*           users:((sshd,pid=1,fd=2))"
    ep = _parse_one_line(line)
    assert ep is not None
    assert ep.protocol == "tcp"
    assert ep.local_port == 22
    assert "0.0.0.0" in ep.local_address
