from payload_fetcher.user_agents import REALISTIC_USER_AGENTS, pick_user_agent


def test_pool_has_multiple_distinct_entries():
    assert len(REALISTIC_USER_AGENTS) >= 5
    assert len(set(REALISTIC_USER_AGENTS)) == len(REALISTIC_USER_AGENTS)


def test_pool_does_not_self_identify():
    # The bug this guards against: the old static default ("Mozilla/5.0 (AssemblyLine
    # PayloadFetcher)") let malware-hosting infrastructure fingerprint and
    # block/decoy-serve requests from this service instead of serving the real payload.
    for ua in REALISTIC_USER_AGENTS:
        assert "assemblyline" not in ua.lower()
        assert "payloadfetcher" not in ua.lower()
        assert ua.startswith("Mozilla/5.0")  # matches real browser UA shape


def test_pick_user_agent_returns_pool_member():
    for _ in range(20):
        assert pick_user_agent() in REALISTIC_USER_AGENTS
