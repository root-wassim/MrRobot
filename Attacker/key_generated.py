from Cryptodome.PublicKey import RSA

key = RSA.generate(4096)
private_key = key.export_key()
public_key = key.publickey().export_key()


with open("private.pem", "wb") as priv_file:
    priv_file.write(private_key)

with open("public.pem", "wb") as pub_file:
    pub_file.write(public_key)