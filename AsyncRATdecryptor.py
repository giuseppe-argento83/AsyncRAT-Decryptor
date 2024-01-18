import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
import base64
import io
from Crypto.Cipher import AES

class DecryptClass:
    Salt = bytes([191,235,30,86,251,205,151,59,178,25,2,36,48,165,120,67,0,61,86,68,210,30,98,185,212,241,128,231,230,195,57,65])
    EncKey = None
        
    def __init__(self, password):
        if not password:
            raise ValueError("masterKey cannot be null or empty.")

        derived_key = PBKDF2(password, self.Salt, dkLen=32, count=50000, hmac_hash_module=SHA1)
        
        self.EncKey = derived_key
    
    def __unpad(self, plaintext):
        last_character = plaintext[len(plaintext) - 1:]
        bytes_to_remove = ord(last_character)
        return plaintext[:-bytes_to_remove]
        
    def aes_decryptor(self, encrypted_bytes):
        if encrypted_bytes is None:
            raise ValueError("Input cannot be null.")

        
        aes_crypto_provider = AES.new(
            key=self.EncKey,
            mode=AES.MODE_CBC,
            IV=encrypted_bytes[32:48]
        )

        decrypted_data = aes_crypto_provider.decrypt(encrypted_bytes[48:])

        return self.__unpad(decrypted_data.decode("utf-8"))

    def check_authentication_code(self, expected_mac, actual_mac):
        #print(expected_mac, actual_mac)
        return expected_mac == actual_mac
        

# Esempio di utilizzo
password = "b3YyUGZnMXU4b1MxcEZ3QW91aTRxbkdZSDhPdlZucWs="
decryptor = DecryptClass(base64.b64decode(password))
config = {
"TcpPorts":"wzsgUHg2M6X/mTbOw1YsH4bXDzTAZ2d1zwDjyNniON3l83achQPZT83SBjpcKwj7t8cTbNbdBx0yIgtVDSh+Gg==",
"Hosts":"WIfy2yo7ihQN2on3Y+QpogGZ0KTbnMyB8CVoaFsGbXznCDCp2GdyiCqa4UGJBSIo/YggNxtj8EyNKK/+zv1l+w1TNvQHP23rwGb1mqDPhSA=",
"Version":"/QMEVphsdNk2fpGtDsYVyE+wTN/PJ0roOaO6Y5eFCRfaMgP7HfCZnL8oKTWZrKg70W+TFJzLUJC8NJ+MQ9TW0A==",
"FlagPersistence":"J1AHNNWHo1R27/edrXHroO7YNlLYeaEOuRMCr250d2D9mXn/YfUDGJERH9u0OQ/AjVZGYTRglfu1b5VdQ2qUGg==",
"Mtx":"jW66+q4nUfo+76CFgALYUgd+fpqooB/yQRs7aoPMpxwhjCtvOQAsjFQmuLDVRpZbwO3f4RBG6Vqp+gO9m5OQ5RtjKc4Or0EGvxV7jXN86C0=",
"ServerSignature":"dCjyPcIh0p+py7SxuoiL5C8iT4N+DAFwXITm+fXzno5Yx0O7rWnDregb38sRcYEhY9b/VXUHSlhlDYL0hu49N5tGcq6WhzCBpvLtkbpyUaCZTFe5F1xDi8zhdEanN44FYVWbI4MPuYAPTqag69e3z4HCgc1B6QYZhBmH7QwbvuWrXkok14R9K9Dg0hS4NZWW/VNYgY+w6nA+JDdXEMwJAqJm6fZ5q5qi+coeO/+uJMvF3Lodmdkm0TDc2WOI7AlRN9l0bQKWHXzhcsMWY//0f98Kg18xjwC/4qSx09RKGH09mWhdmkqxOACmo6Q6raV8bhTxHUf2kKbuavigDUyqRvtsIh8hQQZmFcF7OIZTtP/bxRTMyR6dQM/Lzpl7nD7japaRJHsbedlIvVEevawirWJ7hsO5q+4jP1P3JOmDnRRzG/nzwQcXApWrCB8WnkhSOeXaHJ7mkyK5BUACURBO5zsyCktWaNxuuVVyTx/ZSU4XekDQDrYKDL3of0dNe+xksrz6BlzqqDK3XOQHli1YfpEb2m/+yn8KwhsCP0w8mREPK37jYshn9qG08HtbRodTksbIyggZGZJU9MEUhP7EG4WdsCNUxUn+D52NM9JW/mndGlhyg64TOHEVUOO/E6wX44cA4/f1NOWG/zC3FxnUyBeTp4W0dT+Ry3PAzEZ9GLHKYPveiiKNnyE3hyQ5aFsj+0CgKN6fO6s2Jc+2fbkRfWFNmLAuxbWw9zJuo5HZUFsEVAOCwzhrx1CuilJjuRo1UeEZzq5L9o5c4YjTRLKnxUp/2gjNlj/I9O2/SOGRfFjkQil2z+9oFH5bNBeoD+PX1hKO7rrxc06HLVkshBzgGTHpT+Jq47g1PoA/TD6tMfmTTGtI+EWECo6MODTr06hjHtQOPcmES2ZQYz/bZ/GmI0L29Zt/nQ52CfaSf69Ad7fdZg2Xq2kugvd8tU4p23bTJuxBc5MAAeM/xsFF9K6F1A==",
"FlagAntiDebug":"h2tsbcuHxchmMy4AVnkzFugam3CSiX6d2+j5vuuKxSvuUpKT9z/o++y0zQNTiQUb3UiBpEWO5uZHG1m0B0yGMw==",
"FlagKeyLogger":"HpK3i5n1BlMOOa3CnUnrLwO5rFm71bH6Ew+4v27CjMIGb81SdWc84lSfnWNnoApwvLZhrwT1kY5fsQm7PlTWaQ==",
"Pastebin":"bKvsxNBO/GbWxwEd4pSQhMQRzg02J0RJ92UNzDetZmRJJfKdR/TkYYX+ZZMRY3vqKIaEspPNhrfze8+2exiVug==",
"FlagCritical":"uLNLAr0B4dO1+YFxLwJT7IKE/LspNKBWwYzbsjX1evHrnyzh2OIHdCdXmpQjn3FrtMXS+ShSJjLefVLqDX9jKQ==",
"Group":"bQDLZ2EgJFFWxaYes6+D5OVghMCk4lSYRpaDymzH90rkpFj9yGEP8EPyCE+UENo78FlsXA0o3d5NDuKfJ2CZuQ=="
}

for k,v in config.items():
    print("{}:{}".format(k, decryptor.aes_decryptor(base64.b64decode(v))))
#print(decryptor.AuthKey)
