from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64encode

message = "我是要加密的訊息"
new_key = RSA.generate(1024)
prikey = new_key.exportKey("PEM").decode('ascii')
pubkey = new_key.publickey().exportKey("PEM").decode('ascii')

pubKeyObj = RSA.import_key(pubkey)
priKeyObj = RSA.import_key(prikey)
cipher = PKCS1_v1_5.new(pubKeyObj)
emsg = cipher.encrypt(message.encode())

e = PKCS1_v1_5.new(priKeyObj)
decrypt_text = e.decrypt(emsg, None).decode()
print("加密->", b64encode(emsg))
print("解密的訊息->",decrypt_text)