from Crypto.PublicKey import RSA

# Generate RSA keys
key = RSA.generate(2048)

# Save private key
with open("private.pem", "wb") as f:
    f.write(key.export_key())

# Save public key
with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("Keys generated: private.pem & public.pem")

