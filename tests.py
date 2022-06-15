import random
import secrets
import unittest
from decimal import Decimal

from webcash.exceptions import AmountException
from webcash.webcashbase import LEGALESE, PublicWebcash, SecretWebcash, secret_to_public

_ACKED_DISCLOSURES = {disclosure_name: True for disclosure_name in LEGALESE.keys()}


class SecretWebcashTestCase(unittest.TestCase):
    def test_bank_webcash_constructor(self):
        n1 = SecretWebcash(1, 2)
        self.assertEqual(n1.amount, 1)
        self.assertEqual(n1.secret_value, 2)

        amount = 100
        secret_value = secrets.token_hex(8)
        n2 = SecretWebcash(amount, secret_value)
        self.assertEqual(n2.amount, amount)
        self.assertTrue(type(n2.secret_value) == str)

    def test_bank_webcash_string_serialization(self):
        amount = 500
        secret_value = "feedbeef"
        n1 = SecretWebcash(amount, secret_value)
        self.assertEqual(str(n1), f"e{amount}:secret:{secret_value}")

    def test_bank_webcash_repr(self):
        amount = 120
        n1 = SecretWebcash(amount, "feedbeef")
        self.assertEqual(
            repr(n1), f'SecretWebcash(amount="{amount}", secret_value="feedbeef")'
        )

    def test_amounts(self):
        count = 12
        amounts = [random.randrange(1, 100 + 1) for x in range(0, count)]
        webcashes = [
            SecretWebcash(amount=amounts[x], secret_value=secrets.token_hex(8))
            for x in range(0, count)
        ]
        self.assertEqual(len(webcashes), count)
        self.assertEqual(sum(amounts), sum([webcash.amount for webcash in webcashes]))

    def test_small_amounts(self):
        amounts = [
            1,
            Decimal("0.1"),
            Decimal("0.001"),
            Decimal("0.0001"),
            Decimal("0.00001"),
            Decimal("0.00000001"),
            Decimal("0.12345678"),
        ]
        webcashes = [
            SecretWebcash(amount=amount, secret_value=secrets.token_hex(8))
            for amount in amounts
        ]
        assert all([webcashes[x].amount == amounts[x] for x in range(0, len(amounts))])
        assert all(
            [
                SecretWebcash.deserialize(str(webcash)) == webcash
                for webcash in webcashes
            ]
        )
        assert all(
            [
                SecretWebcash.deserialize(str(webcash)).amount == webcash.amount
                for webcash in webcashes
            ]
        )

        expectations = [
            {
                "val": Decimal("1E-8"),
                "in": "e1E-8:secret:feedbeef",
                "out": "e0.00000001:secret:feedbeef",
            },
            {
                "val": Decimal("1E-8"),
                "in": "e0.00000001:secret:feedbeef",
                "out": "e0.00000001:secret:feedbeef",
            },
            {
                "val": Decimal("1E-6"),
                "in": "e1E-6:secret:feedbeef",
                "out": "e0.000001:secret:feedbeef",
            },
            {
                "val": Decimal("1E-6"),
                "in": "e0.00000100:secret:feedbeef",
                "out": "e0.000001:secret:feedbeef",
            },
            {
                "val": Decimal("100.001"),
                "in": "e100.00100000:secret:feedbeef",
                "out": "e100.001:secret:feedbeef",
            },
        ]
        for exp in expectations:
            swc = SecretWebcash.deserialize(exp["in"])
            self.assertEqual(str(swc), exp["out"])
            self.assertEqual(swc.amount, exp["val"])

    def test_invalid_amounts(self):
        amount = Decimal("0.123456789")  # too many decimals
        self.assertRaises(
            AmountException,
            SecretWebcash,
            amount=amount,
            secret_value=secrets.token_hex(8),
        )


if __name__ == "__main__":
    unittest.main()
