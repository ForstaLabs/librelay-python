
def unencode_addr(addr):
    return addr.split(".")


class RequestError(Exception):

    def __init__(self, message, response, code, text, json):
        super().__init__(message)
        self.response = response
        self.code = code
        self.text = text
        self.json = json
