# CS 7530 Group Assignment
# Professor Zhang November 2024
# Sameer Jehan Nancy, Bhavya Nanga, Tyler Ebersold
# File for RSA authentication/encryption and decryption to be imported into driver file
from math import gcd

# Extended Euclidean Algorithm to compute the modular inverse
def extended_euclidean_algorithm(a, b):
    if gcd(a, b) != 1:
        return None
    old_p, p = a, b
    old_q, q = 1, 0
    old_t, t = 0, 1
    # Computes modular inverse for private key
    while p != 0:
        quotient = old_p // p
        old_p, p = p, old_p - quotient * p
        old_q, q = q, old_q - quotient * q
        old_t, t = t, old_t - quotient * t

    return old_q % b


# Square and Multiply (modular exponentiation) function for encryption/decryption
def square_and_multiply(x, e, n):
    e = bin(e)[2:]  # Convert exponent to binary
    result = 1
    for bit in e:
        result = (result * result) % n  # Square the result
        if bit == '1':
            result = (result * x) % n  # Multiply by x if the bit is 1
    return result


# Key Generation: Generate public and private keys
def generate_keys():
    # Given primes p and q
    p = 61
    q = 83
    n = p * q
    tn = (p - 1) * (q - 1)  # Euler's totient function
    e = 17  # Public exponent
    d = extended_euclidean_algorithm(e, tn)  # Compute private exponent d using EEA
    return (e, n), d  # Return public key (e, n) and private key d


# Encrypt function for chunks
def rsa_encrypt_chunk(chunk, e, n):
    # Encrypt each chunk using the RSA formula
    encrypted_chunk = square_and_multiply(chunk, e, n)
    return encrypted_chunk


# Decrypt function for chunks
def rsa_decrypt_chunk(encrypted_chunk, d, n):
    # Decrypt each chunk using the RSA formula
    decrypted_chunk = square_and_multiply(encrypted_chunk, d, n)
    return decrypted_chunk


def authenticate(message):
    # Convert the message to integer
    message_int = int(message, 2)
    message_hex = hex(message_int)[2:]  # Convert to hex string
    print(f"========RSA AUTHENTICATION========")  # nameplate for debugging purposes
    print(f"Original Message (Hex): {message_hex}")

    # Generate public and private keys
    (e, n), d = generate_keys()
    # break message into chunks for encryption and decryption
    if message_int >= n:
        print("Message too large, breaking into smaller chunks")
        chunk_size = 1
        # Small modulus so had to use 1 as chunk size

        # Ensure the message length is a multiple of chunk_size (pad if necessary)
        if len(message_hex) % chunk_size != 0:
            message_hex = message_hex.zfill(len(message_hex) + (chunk_size - len(message_hex) % chunk_size))

        # Split the message into chunks of chunk_size (in hex digits)
        message_chunks = [message_hex[i:i + chunk_size] for i in range(0, len(message_hex), chunk_size)]
        print(f"Message chunks: {message_chunks}")

        # Encrypt each chunk
        encrypted_chunks = []
        for chunk in message_chunks:
            # for each chunk, hex to int for encryption
            chunk_int = int(chunk, 16)
            if chunk_int < n:
                encrypted_chunk = rsa_encrypt_chunk(chunk_int, e, n)
                encrypted_chunks.append(encrypted_chunk)
            else:
                print(f"Chunk {chunk} too large for encryption!")

        print(f"Encrypted chunks: {encrypted_chunks}")
        # Decrypt each chunk and reconstruct the message
        decrypted_chunks = []
        for encrypted_chunk in encrypted_chunks:
            decrypted_chunk = rsa_decrypt_chunk(encrypted_chunk, d, n)
            decrypted_chunks.append(hex(decrypted_chunk)[2:])  # Convert back to hex string|Remove '0x' prefix

        # Reconstruct the decrypted message by joining the chunks
        decrypted_message = ''.join(decrypted_chunks)

        print(f"Decrypted Message (Hex): {decrypted_message}")

        # Strip leading zeros from the final decrypted message to match the original
        decrypted_message_stripped = decrypted_message.lstrip("0")

        # Ensure the length of the decrypted message is the same as the original
        if decrypted_message_stripped == message_hex:
            print("Decryption successful! The decrypted message matches the original.")
        else:
            print("Decryption failed! The decrypted message does not match the original.")
            print(f"Decrypted Message: {decrypted_message_stripped}")
    else:
        # If message is small enough, encrypt it as a whole, i.e. its smaller byte size than n modulus value
        encrypted_message = rsa_encrypt_chunk(message_int, e, n)
        print(f"Encrypted Message (Integer): {encrypted_message}")
        print(f"Encrypted Message (Hex): {hex(encrypted_message)[2:]}")

        # Decrypt the message
        decrypted_message = rsa_decrypt_chunk(encrypted_message, d, n)
        decrypted_message_hex = hex(decrypted_message)[2:]

        # Strip leading zeros from the decrypted message
        decrypted_message_stripped = decrypted_message_hex.lstrip("0")

        if decrypted_message_stripped == message_hex:
            print("Decryption successful! The decrypted message matches the original.")
        else:
            print("Decryption failed! The decrypted message does not match the original.")
            print(f"Decrypted Message: {decrypted_message_stripped}")
