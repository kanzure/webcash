class WebcashException(Exception):
    """
    Base class for webcash exceptions.
    """
    pass

class AmountException(WebcashException):
    """
    Amount precision should be at most 8 decimals, or some other issue with the
    amount.
    """
    pass

class DeserializationException(WebcashException):
    """
    Error for deserialization issues.
    """
    pass


