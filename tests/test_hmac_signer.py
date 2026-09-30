from src.engine.hmac_signer import HmacSigner, generate_unverified_token


class TestHmacSigner:
    def test_sign_returns_32_bytes(self):
        signer = HmacSigner()
        key = b"a" * 32
        result = signer.sign(key, 1234, "read_file", 1000000)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_sign_deterministic(self):
        signer = HmacSigner()
        key = b"b" * 32
        r1 = signer.sign(key, 1, "search", 2000)
        r2 = signer.sign(key, 1, "search", 2000)
        assert r1 == r2

    def test_sign_different_inputs_different_output(self):
        signer = HmacSigner()
        key = b"c" * 32
        r1 = signer.sign(key, 1, "read_file", 1000)
        r2 = signer.sign(key, 2, "read_file", 1000)
        assert r1 != r2

    def test_verify_roundtrip(self):
        signer = HmacSigner()
        key = b"d" * 32
        cid = signer.sign(key, 42, "send_email", 9999)
        assert signer.verify(key, cid, 42, "send_email", 9999) is True

    def test_verify_wrong_key_fails(self):
        signer = HmacSigner()
        cid = signer.sign(b"k1" + b"\x00" * 30, 1, "search", 1)
        assert signer.verify(b"k2" + b"\x00" * 30, cid, 1, "search", 1) is False

    def test_verify_wrong_pid_fails(self):
        signer = HmacSigner()
        key = b"e" * 32
        cid = signer.sign(key, 1, "search", 1)
        assert signer.verify(key, cid, 2, "search", 1) is False

    def test_sign_different_ttl_different_output(self):
        """不同 TTL 值产生不同签名，防止 TTL 固定的重放"""
        signer = HmacSigner()
        key = b"f" * 32
        r1 = signer.sign(key, 1, "read_file", 1000, ttl_ns=5_000_000_000)
        r2 = signer.sign(key, 1, "read_file", 1000, ttl_ns=3_000_000_000)
        assert r1 != r2

    def test_verify_with_custom_ttl(self):
        signer = HmacSigner()
        key = b"g" * 32
        cid = signer.sign(key, 99, "db_query", 5555, ttl_ns=2_000_000_000)
        assert signer.verify(key, cid, 99, "db_query", 5555, ttl_ns=2_000_000_000)
        # 不同 TTL 验签失败
        assert not signer.verify(key, cid, 99, "db_query", 5555, ttl_ns=1_000_000_000)

    def test_generate_unverified_token_prefix(self):
        result = generate_unverified_token()
        assert isinstance(result, bytes)
        assert result[:11] == b"UNVERIFIED_"
        assert len(result) > 11
