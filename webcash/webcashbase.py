import decimal
import secrets
import hashlib

from .exceptions import (
    AmountException,
    DeserializationException,
)

LEGALESE = {
    "terms": "I acknowledge and agree to the Terms of Service located at https://webcash.tech/terms",
}

def compute_target(difficulty_target_bits):
    """
    Calculate a target hash given a difficulty.
    """
    return 2 ** (256 - difficulty_target_bits)

def verify_hash(work, value):
    """
    Check that the given preimage corresponds to the given PoW hash.
    """
    work_check = int(hashlib.sha256(bytes(value, "ascii")).hexdigest(), 16)
    if work_check != work:
        return False
    else:
        return True

def check_work_meets_target(work, difficulty_target_bits):
    """
    Check that the PoW hashwork meets a certain difficulty.
    """
    target = compute_target(difficulty_target_bits)
    if work <= target:
        return True
    else:
        return False

def generate_secret_value(size=32):
    """
    generate a random secret
    """
    return secrets.token_hex(size)

def secret_to_public(secret_value: str):
    """
    Convert a secret into a public value. Make a commitment to the secret.
    """
    return hashlib.sha256(bytes(str(secret_value), "ascii")).hexdigest()

def validate_amount_decimals(amount: decimal.Decimal):
    """
    Take an amount and raise an error if it has too many decimals.
    """
    valid = (((amount * 10**8) % 1) == 0)
    if not valid:
        raise AmountException("Amount precision should be at most 8 decimals.")
    else:
        return True

def amount_to_str(amount):
    """
    Serialize an amount into a string value, used for representing different
    webcash when serializing webcash.
    """
    if amount == 0:
        raise AmountException("Amount can't be 0.")
    elif amount == None:
        return "?"
    else:
        return str(amount)

def deserialize_amount(amount: str):
    """
    Take an amount in string format and convert it into a decimal object.
    """
    if amount != None and amount != "?":
        amount = decimal.Decimal(amount)
        if amount == 0:
            raise AmountException("Amount can't be 0.")
        else:
            validate_amount_decimals(amount)
    else:
        amount = None
    return amount

def deserialize_webcash(value: str):
    """
    Take any kind of webcash and instantiate an object with the values specified
    by the serialized webcash.
    """
    if ":" in value:
        if value.count(":") < 2:
            raise DeserializationException("Don't know how to deserialize this webcash.")

        parts = value.split(":")
        amount_part = parts[0]
        if amount_part[0][0] == "e":
            amount_part = amount_part[1:]
        amount = deserialize_amount(amount_part)

        public_or_secret = parts[1]
        if public_or_secret not in ["public", "secret"]:
            raise DeserializationException("Can't deserialize this webcash because it needs to be either public/secret.")

        data = parts[2]
        if len(parts) > 3:
            # undo split on the rest of the data
            data = ":".join(parts[2:])

        if public_or_secret == "secret":
            return SecretWebcash(amount=amount, secret_value=data)
        elif public_or_secret == "public":
            return PublicWebcash(amount=amount, hashed_value=data)
        else:
            raise DeserializationException("Not sure how to deserialize this webcash.")
    else:
        raise DeserializationException("Given webcash needs to be better structured.")
        #hashed_value = value
        #return cls(None, hashed_value)

def check_legal_agreements(webcash_wallet):
    """
    webcash disclosures must be acknowledged before the user can use this
    product.
    """
    acknowledgements = webcash_wallet["legalese"].items()
    expected = LEGALESE.keys()
    has_expected = all([expectation in webcash_wallet["legalese"].keys() for expectation in expected])
    agreement = all(ack[1] == True for ack in acknowledgements)
    return has_expected and agreement

class SecretWebcash:
    """
    SecretWebcash is an object that serializes an amount and a secret_value.
    The secret_value is a secret that can be given to another user as a way to
    transfer value.
    """

    # When "amount" is None, it means that the value is unknown, not that there
    # is no value. For no value the amount would have to be "0", but there's no
    # reason for the system to record 0-value unspents anyway. The client does
    # not have to remember the value of "amount", but the server most certainly
    # must.
    amount: decimal.Decimal

    # Critical component of the serial number-- a random secret_value chosen by
    # the user. Stored as a string of big-endian hex.
    # secret_value = secrets.token_hex(32)
    secret_value: str

    def __init__(self, amount: str, secret_value: str):
        self.amount = deserialize_amount(amount)
        self.secret_value = secret_value

    def __repr__(self):
        amount = amount_to_str(self.amount)
        return f"SecretWebcash(amount=\"{self.amount}\", secret_value=\"{self.secret_value}\")"

    def __str__(self):
        amount = amount_to_str(self.amount)
        return f"e{amount}:secret:{self.secret_value}"

    def serialize(self):
        return str(self)

    @classmethod
    def deserialize(cls, value: str):
        webcash = deserialize_webcash(value)
        return webcash

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if self.secret_value == other.secret_value:
                return True
            else:
                return False
        elif isinstance(other, PublicWebcash):
            if self.to_public() == other:
                return True
            else:
                return False
        else:
            #return super().__eq__(other)
            return NotImplemented

    def to_public(self):
        """
        Take a SecretWebcash and make it into a PublicWebcash.
        """
        hashed_value = secret_to_public(self.secret_value)
        return PublicWebcash(amount=self.amount, hashed_value=hashed_value)

class PublicWebcash:
    """
    PublicWebcash is an object that serializes an amount and a H(secret_value)
    value. The secret_value is not revealed by displaying a PublicWebcash. It
    can only be used to check whether webcash has been spent or not.
    """

    # described in SecretWebcash
    amount: decimal.Decimal

    # b2x(hashlib.sha256(secret_value).digest())
    hashed_value: str

    def __init__(self, amount: str, hashed_value: str):
        self.amount = deserialize_amount(amount)
        self.hashed_value = hashed_value

    def __repr__(self):
        amount = amount_to_str(self.amount)
        return f"PublicWebcash(amount=\"{self.amount}\", hashed_value=\"{self.hashed_value}\")"

    def __str__(self):
        amount = amount_to_str(self.amount)
        return f"e{amount}:public:{self.hashed_value}"

    def serialize(self):
        return str(self)

    @classmethod
    def deserialize(cls, value: str, convert_secret_to_public=False):
        webcash = deserialize_webcash(value)
        if convert_secret_to_public == True and isinstance(webcash, SecretWebcash):
            return webcash.to_public()
        else:
            return webcash

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if self.hashed_value == other.hashed_value:
                return True
            else:
                return False
        elif isinstance(other, SecretWebcash):
            if secret_to_public(other.secret_value) == self.hashed_value:
                return True
            else:
                return False
        else:
            #return super().__eq__(other)
            return NotImplemented
