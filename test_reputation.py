import unittest
from reputation import (
    Report,
    ReputationProfile,
    add_prefix_and_checksum,
    validate_key_with_checksum,
    generate_secret_key,
    derive_pubkey_from_secret,
)

class ReputationTests(unittest.TestCase):

    def test_prefix_and_checksum(self):
        raw_key = "abcdef0123456789" * 4  # 64 hex chars
        sk = add_prefix_and_checksum("SK", raw_key)
        self.assertTrue(validate_key_with_checksum(sk, "SK"))

        invalid_key = sk[:-1] + "0"
        self.assertFalse(validate_key_with_checksum(invalid_key, "SK"))

    def test_generate_and_derive_key(self):
        sk = generate_secret_key()
        self.assertTrue(sk.startswith("SK"))
        pk = derive_pubkey_from_secret(sk)
        self.assertTrue(pk.startswith("PK"))
        self.assertTrue(validate_key_with_checksum(pk, "PK"))

    def test_report_creation_and_summary(self):
        reporter = "PK03" + "a"*64 + "abcd"  # fake pubkey with checksum
        target = "PK03" + "b"*64 + "abcd"
        r1 = Report("positive", 0.01, "Good report", reporter, target)
        r2 = Report("negative", 0.02, None, reporter, target)
        profile = ReputationProfile(pubkey=target, alias=None, reports=[r1, r2])

        pos_count = sum(1 for r in profile.reports if r.report_type == "positive")
        neg_count = sum(1 for r in profile.reports if r.report_type == "negative")
        self.assertEqual(pos_count, 1)
        self.assertEqual(neg_count, 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
