class WebcashException(Exception):
    """
    Base class for webcash exceptions.
    """


class AmountException(WebcashException):
    """
    Amount precision should be at most 8 decimals, or some other issue with the
    amount.
    """


class DeserializationException(WebcashException):
    """
    Error for deserialization issues.
    """
