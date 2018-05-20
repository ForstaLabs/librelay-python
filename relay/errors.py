class RelayError(Exception):
    pass


class IdentityKeyError(RelayError):

    def __init__(self, addr, key):
        self.identitykey = key;
        self.addr = addr
        self.accepted = False
        message = f"The identity of {addr} has changed"
        super().__init__(message)


class IncomingIdentityKeyError(IdentityKeyError):
    pass


class OutgoingIdentityKeyError(IdentityKeyError):
    pass


class OutgoingMessageError(RelayError):

    def __init__(self, addr, message, timestamp, http_error=None):
        if http_error is not None:
            self.code = http_error.code
            message = http_error.message
        super().__init__(message)


class SendMessageError(RelayError):

    def __init__(self, addr, http_error):
        self.addr = addr;
        self.code = http_error.code;
        super().__init__(http_error.message)


class MessageError(RelayError):

    def __init__(self, message, http_error):
        self.code = http_error.code;
        super().__init__(http_error.message)


class UnregisteredUserError(RelayError):

    def __init__(self, addr, http_error):
        self.addr = addr
        self.code = http_error.code;
        super().__init__(http_error.message)


class ProtocolError(RelayError):

    def __init__(self, code, response):
        if code > 999 or code < 100:
            code = -1
        self.code = code
        self.response = response


class NetworkError(RelayError):
    pass
