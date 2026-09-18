# RSA Cryptosystem with Digital Signatures and Performance Analysis

import secrets
import hashlib
import time
import matplotlib.pyplot as plt


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def euler_totient(p, q):
    return (p - 1) * (q - 1)


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return gcd_value, x, y


def modular_inverse(e, phi):
    gcd_value, x, y = extended_gcd(e, phi)

    if gcd_value != 1:
        raise ValueError("Modular inverse does not exist.")

    return x % phi


def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:

        if exponent % 2 == 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent = exponent // 2

    return result
#Prime Number Generation and RSA Key Generation
def is_prime(n, rounds=10):

    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    if n in small_primes:
        return True

    for prime in small_primes:
        if n % prime == 0:
            return False

    d = n - 1
    r = 0

    while d % 2 == 0:
        d = d // 2
        r = r + 1

    for _ in range(rounds):

        a = secrets.randbelow(n - 3) + 2

        x = modular_exponentiation(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):

            x = modular_exponentiation(x, 2, n)

            if x == n - 1:
                break

        else:
            return False

    return True
#This uses the Miller–Rabin primality test to check whether a generated number is probably prime.
#Generate Prime Numbers
def generate_prime(bits):

    while True:

        number = secrets.randbits(bits)

        number = number | (1 << (bits - 1))
        number = number | 1

        if is_prime(number):
            return number
#RSA Key Generation
def generate_rsa_keys(key_size):

    prime_bits = key_size // 2

    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)

    while p == q:
        q = generate_prime(prime_bits)

    n = p * q

    phi = euler_totient(p, q)

    e = 65537

    while gcd(e, phi) != 1:
        e = e + 2

    d = modular_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key
#RSA Encryption and Decryption
#Convert Text into a Number
def text_to_number(message):
    message_bytes = message.encode("utf-8")
    return int.from_bytes(message_bytes, byteorder="big")
#Convert Number Back into Text
def number_to_text(number):

    if number == 0:
        return ""

    length = (number.bit_length() + 7) // 8

    message_bytes = number.to_bytes(
        length,
        byteorder="big"
    )

    return message_bytes.decode("utf-8")
#RSA Encryption
def rsa_encrypt(message, public_key):

    e, n = public_key

    message_number = text_to_number(message)

    if message_number >= n:
        raise ValueError(
            "Message is too large for the selected RSA key size."
        )

    ciphertext = modular_exponentiation(
        message_number,
        e,
        n
    )

    return ciphertext
#RSA Decryption
def rsa_decrypt(ciphertext, private_key):

    d, n = private_key

    message_number = modular_exponentiation(
        ciphertext,
        d,
        n
    )

    return number_to_text(message_number)
#RSA Digital Signatures
#Create a Hash of the Message
def hash_message(message):

    message_bytes = message.encode("utf-8")

    hash_value = hashlib.sha256(message_bytes).digest()

    return int.from_bytes(hash_value, byteorder="big")
#Generate the Digital Signature
def generate_signature(message, private_key):

    d, n = private_key

    message_hash = hash_message(message)

    signature = modular_exponentiation(
        message_hash,
        d,
        n
    )

    return signature
#Verify the Digital Signature
def verify_signature(message, signature, public_key):

    e, n = public_key

    message_hash = hash_message(message)

    verified_hash = modular_exponentiation(
        signature,
        e,
        n
    )

    return verified_hash == (message_hash % n)
# PERFORMANCE ANALYSIS
def measure_performance(key_size, message, repetitions=5):

    key_generation_times = []
    encryption_times = []
    decryption_times = []
    signing_times = []
    verification_times = []

    for _ in range(repetitions):

        start = time.perf_counter()
        public_key, private_key = generate_rsa_keys(key_size)
        end = time.perf_counter()

        key_generation_times.append(end - start)

        start = time.perf_counter()
        ciphertext = rsa_encrypt(message, public_key)
        end = time.perf_counter()

        encryption_times.append(end - start)

        start = time.perf_counter()
        rsa_decrypt(ciphertext, private_key)
        end = time.perf_counter()

        decryption_times.append(end - start)

        start = time.perf_counter()
        signature = generate_signature(message, private_key)
        end = time.perf_counter()

        signing_times.append(end - start)

        start = time.perf_counter()
        verify_signature(message, signature, public_key)
        end = time.perf_counter()

        verification_times.append(end - start)

    return {
        "Key Size": key_size,
        "Key Generation": sum(key_generation_times) / repetitions,
        "Encryption": sum(encryption_times) / repetitions,
        "Decryption": sum(decryption_times) / repetitions,
        "Signing": sum(signing_times) / repetitions,
        "Verification": sum(verification_times) / repetitions
    }


def performance_analysis():

    message = "HELLO RSA"

    key_sizes = [512, 1024, 2048]

    results = []

    for key_size in key_sizes:

        print("\nTesting RSA key size:", key_size, "bits")

        result = measure_performance(
            key_size,
            message,
            repetitions=5
        )

        results.append(result)

    return results

# DISPLAY PERFORMANCE RESULTS

def display_results(results):

    print("\n")
    print("=" * 100)
    print("RSA PERFORMANCE ANALYSIS RESULTS")
    print("=" * 100)

    print(
        f"{'Key Size':<12}"
        f"{'Key Generation':<20}"
        f"{'Encryption':<16}"
        f"{'Decryption':<16}"
        f"{'Signing':<16}"
        f"{'Verification':<16}"
    )

    print("-" * 100)

    for result in results:

        print(
            f"{result['Key Size']:<12}"
            f"{result['Key Generation']:<20.6f}"
            f"{result['Encryption']:<16.6f}"
            f"{result['Decryption']:<16.6f}"
            f"{result['Signing']:<16.6f}"
            f"{result['Verification']:<16.6f}"
        )

    print("=" * 100)

# GENERATE PERFORMANCE GRAPHS

def generate_graphs(results):

    key_sizes = [
        result["Key Size"]
        for result in results
    ]

    key_generation = [
        result["Key Generation"]
        for result in results
    ]

    encryption = [
        result["Encryption"]
        for result in results
    ]

    decryption = [
        result["Decryption"]
        for result in results
    ]

    signing = [
        result["Signing"]
        for result in results
    ]

    verification = [
        result["Verification"]
        for result in results
    ]

    # Graph 1: Key Generation Time

    plt.figure()

    plt.plot(
        key_sizes,
        key_generation,
        marker="o"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Key Generation Performance")
    plt.grid(True)

    plt.show()


    # Graph 2: Encryption and Decryption Time

    plt.figure()

    plt.plot(
        key_sizes,
        encryption,
        marker="o",
        label="Encryption"
    )

    plt.plot(
        key_sizes,
        decryption,
        marker="o",
        label="Decryption"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Encryption and Decryption Performance")
    plt.legend()
    plt.grid(True)

    plt.show()


    # Graph 3: Digital Signature Time

    plt.figure()

    plt.plot(
        key_sizes,
        signing,
        marker="o",
        label="Signing"
    )

    plt.plot(
        key_sizes,
        verification,
        marker="o",
        label="Verification"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Digital Signature Performance")
    plt.legend()
    plt.grid(True)

    plt.show()
#Main RSA Demonstration
def main():

    message = "HELLO RSA"

    print("=" * 60)
    print("RSA CRYPTOSYSTEM WITH DIGITAL SIGNATURES")
    print("=" * 60)

    print("\nGenerating RSA keys...")

    public_key, private_key = generate_rsa_keys(1024)

    print("\nPublic Key:")
    print(public_key)

    print("\nPrivate Key:")
    print(private_key)

    print("\nOriginal Message:")
    print(message)

    ciphertext = rsa_encrypt(
        message,
        public_key
    )

    print("\nEncrypted Message:")
    print(ciphertext)

    decrypted_message = rsa_decrypt(
        ciphertext,
        private_key
    )

    print("\nDecrypted Message:")
    print(decrypted_message)

    signature = generate_signature(
        message,
        private_key
    )

    print("\nDigital Signature:")
    print(signature)

    verification = verify_signature(
        message,
        signature,
        public_key
    )

    print("\nDigital Signature Verification:")
    print(verification)
    print("\nStarting Performance Analysis...")

    results = performance_analysis()
    display_results(results)
    generate_graphs(results)

if __name__ == "__main__":
    main()
#Performance Analysis
#Add the performance function
def measure_performance(key_size, message, repetitions=5):

    key_generation_times = []
    encryption_times = []
    decryption_times = []
    signing_times = []
    verification_times = []
    for _ in range(repetitions):

        start = time.perf_counter()

        public_key, private_key = generate_rsa_keys(key_size)

        end = time.perf_counter()

        key_generation_times.append(end - start)

        start = time.perf_counter()

        ciphertext = rsa_encrypt(
            message,
            public_key
        )

        end = time.perf_counter()

        encryption_times.append(end - start)

        start = time.perf_counter()

        rsa_decrypt(
            ciphertext,
            private_key
        )

        end = time.perf_counter()

        decryption_times.append(end - start)

        start = time.perf_counter()

        signature = generate_signature(
            message,
            private_key
        )

        end = time.perf_counter()

        signing_times.append(end - start)

        start = time.perf_counter()

        verify_signature(
            message,
            signature,
            public_key
        )

        end = time.perf_counter()

        verification_times.append(end - start)

    return {
        "Key Size": key_size,
        "Key Generation": sum(key_generation_times) / repetitions,
        "Encryption": sum(encryption_times) / repetitions,
        "Decryption": sum(decryption_times) / repetitions,
        "Signing": sum(signing_times) / repetitions,
        "Verification": sum(verification_times) / repetitions
    }
#Analyze different key sizes
def performance_analysis():

    message = "HELLO RSA"

    key_sizes = [512, 1024, 2048]

    results = []

    for key_size in key_sizes:

        print("\nTesting RSA key size:", key_size, "bits")

        result = measure_performance(
            key_size,
            message,
            repetitions=5
        )

        results.append(result)

    return results
