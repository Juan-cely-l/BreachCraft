from auth_analysis import analyze_lines


def test_analyze_lines_reports_bruteforce_users_and_ratio() -> None:
    lines = [
        "May 10 01:00:00 kali sshd[1]: "
        "Failed password for root from 185.220.101.5 port 555 ssh2"
        for _ in range(11)
    ]
    lines.extend(
        [
            "May 10 01:01:00 kali sshd[1]: "
            "Failed password for invalid user admin from 10.0.0.2 port 555 ssh2",
            "May 10 01:02:00 kali sshd[1]: "
            "Accepted publickey for daniel from 192.168.1.50 port 22 ssh2",
            "May 10 01:03:00 kali sshd[1]: "
            "Accepted password for user from 192.168.1.51 port 22 ssh2",
        ],
    )

    result = analyze_lines(lines)

    assert result["failed_ips"] == [
        {"ip": "185.220.101.5", "failed_attempts": 11},
    ]
    assert {"user": "root", "attempts": 11} in result["targeted_users"]
    assert {"user": "admin", "attempts": 1} in result["targeted_users"]
    assert result["total_failed"] == 12
    assert result["total_successful"] == 2
    assert result["failed_to_successful_ratio"] == 6.0
