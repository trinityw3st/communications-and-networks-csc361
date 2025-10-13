class URI:
    def __init__(self):
        self.protocol = ""
        self.host = ""
        self.port = 0
        self.filepath = ""
    
    def __str__(self):
        return f"protocol: {self.protocol}, host: {self.host}, port: {self.port}, filepath: {self.filepath}"
    

class Cookie:
    def __init__(self):
        self.cookie_name = ""
        self.expires = None
        self.domain = None
    
    def __str__(self):
        cookie_str = f"cookie name: {self.cookie_name}"
        if self.expires is not None:
            cookie_str += f", expires: {self.expires}"
        if self.domain is not None:
            cookie_str += f", domain: {self.domain}"
        return cookie_str