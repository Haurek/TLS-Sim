class ApplicationData:
    def __init__(self, plain, encrypted):
        self.plain_text = plain
        self.encrypt_text = encrypted
        self.hmac = None

    def show(self):
        print("--------------Application Data--------------")
        print(f"[show]Plain Text: {self.plain_text}")
        print(f"[show]Encrypted Data Length: {len(self.encrypt_text)}")
        print(f"[show]Encrypted Data: {self.encrypt_text}")
        print(f"[show]HMAC: {self.hmac}")
        print("--------------Application Data--------------\n")

    def set_plaintext(self, plaintext):
        self.plain_text = plaintext

    def set_hmac(self, hmac):
        self.hmac = hmac
