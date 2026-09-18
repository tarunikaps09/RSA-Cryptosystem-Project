import streamlit as st
import rsa_project
import matplotlib.pyplot as plt
if "signature" not in st.session_state:
    st.session_state.signature = None

if "public_key" not in st.session_state:
    st.session_state.public_key = None

if "private_key" not in st.session_state:
    st.session_state.private_key = None

if "ciphertext" not in st.session_state:
    st.session_state.ciphertext = None
st.set_page_config(
    page_title="RSA Cryptosystem",
    page_icon="🔐"
)

st.title("RSA Cryptosystem with Digital Signatures")

st.write(
    "An interactive demonstration of RSA encryption, "
    "decryption, digital signatures, and performance analysis."
)
st.header("📘 About")

st.write(
    "This focuses on the implementation of the RSA cryptosystem "
    "with digital signatures and basic performance analysis using Python. "
    "It demonstrates RSA key generation, encryption, decryption, digital "
    "signature generation, signature verification, and the effect of "
    "different RSA key sizes on execution time."
)
st.header("✨ Features")

st.write(
    "\n • RSA key generation using different key sizes\n"
    "\n • RSA encryption and decryption\n"
    "\n • Digital signature generation\n"
    "\n • Digital signature verification\n"
    "\n • Performance analysis of RSA operations\n"
    "\n • Graphical representation of performance results"
)
st.header("🔑 RSA Key Generation")
key_size = st.selectbox(
    "Select RSA Key Size:",
    [512, 1024, 2048]
)
st.write(
    "RSA uses a public key and a private key. "
    "The keys are generated using two prime numbers."
)
st.warning(
    "Note: 512-bit RSA is included only for educational performance "
    "comparison. It is not considered secure for real-world use."
)
if st.button("Generate RSA Keys"):
    public_key, private_key = rsa_project.generate_rsa_keys(key_size)

    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

    st.success("RSA keys generated successfully!")

    st.write("### Public Key")
    st.write(public_key)

    st.write("### Private Key")
    st.write(private_key)
st.header("🔐 RSA Encryption and Decryption")

message = st.text_input(
    "Enter a message to encrypt:",
    placeholder="Example: HELLO"
)
if st.button("Encrypt Message"):
    if message:
        try:
            if st.session_state.public_key is None:
                st.warning("Please generate RSA keys first.")
            else:
                ciphertext = rsa_project.rsa_encrypt(
                    message,
                    st.session_state.public_key
                )

                st.session_state.ciphertext = ciphertext

            st.success("Message encrypted successfully!")

            st.write("### Ciphertext")
            st.write(ciphertext)

        except Exception as e:
            st.error(f"Encryption error: {e}")

    else:
        st.warning("Please enter a message.")
st.subheader("🔓 Decryption")

if st.button("Decrypt Message"):
    if st.session_state.ciphertext is not None:
        try:
            decrypted_message = rsa_project.rsa_decrypt(
                st.session_state.ciphertext,
                st.session_state.private_key
            )

            st.success("Message decrypted successfully!")

            st.write("### Decrypted Message")
            st.write(decrypted_message)

        except Exception as e:
            st.error(f"Decryption error: {e}")

    else:
        st.warning("Please encrypt a message first.")
st.header("✍️ RSA Digital Signature")

st.write(
    "A digital signature is generated using the sender's private key "
    "and verified using the corresponding public key."
)

st.info(
    "Digital signatures help provide authentication and message integrity. "
    "The signature is generated using the sender's private key and verified "
    "using the corresponding public key. Changing the message after signing "
    "will cause verification to fail."
)

signature_message = st.text_input(
    "Enter a message for digital signing:",
    placeholder="Example: This is an authentic message"
)

if st.button("Generate Digital Signature"):
    if signature_message:
        if st.session_state.private_key is not None:

            try:
                signature = rsa_project.generate_signature(
                    signature_message,
                    st.session_state.private_key
                )

                st.session_state.signature = signature

                st.success("Digital signature generated successfully!")

                st.write("### Digital Signature")
                st.write(signature)

            except Exception as e:
                st.error(f"Signature generation error: {e}")

        else:
            st.warning("Please generate RSA keys first.")

    else:
        st.warning("Please enter a message.")
st.subheader("🔎 Verify Digital Signature")

if st.button("Verify Digital Signature"):
    if st.session_state.signature is not None:
        if st.session_state.public_key is not None:

            try:
                verified = rsa_project.verify_signature(
                    signature_message,
                    st.session_state.signature,
                    st.session_state.public_key
                )

                if verified:
                    st.success(
                        "Digital signature is valid."
                    )

                    st.write(
                        "✓ The message is authentic and its integrity has been verified."
                    )
                else:
                    st.error(
                        "Digital signature is invalid."
                    )

                    st.write(
                        "✗ The message has been modified or the signature does not match."
                    )

            except Exception as e:
                st.error(f"Verification error: {e}")

        else:
            st.warning("Please generate RSA keys first.")

    else:
        st.warning("Please generate a digital signature first.")
st.header("📊 Performance Analysis")

st.write(
    "This section measures the execution time of RSA operations "
    "for different key sizes."
)

if st.button("Run Performance Analysis"):

    with st.spinner("Running performance analysis..."):

        results = rsa_project.performance_analysis()

    st.success("Performance analysis completed!")

    st.info(
        "The execution time is measured for RSA key generation, "
        "encryption, decryption, digital signing, and signature verification "
            "using different RSA key sizes. The results help to observe how "
    "increasing the key size affects computational performance."
    )

    st.write("### Performance Results")

    st.caption(
        "Execution time is measured in seconds. "
        "The values represent the average time taken over 5 repetitions."
    )

    st.dataframe(
        results,
        use_container_width=True
    )
    st.write("### Key Generation Time")

    key_sizes = [result["Key Size"] for result in results]
    key_generation_times = [
        result["Key Generation"] for result in results
    ]

    fig1 = plt.figure()

    plt.plot(
        key_sizes,
        key_generation_times,
        marker="o"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Key Generation Performance")

    st.pyplot(fig1)

    plt.close(fig1)
    st.write("### Encryption and Decryption Time")

    encryption_times = [
        result["Encryption"] for result in results
    ]

    decryption_times = [
        result["Decryption"] for result in results
    ]

    fig2 = plt.figure()

    plt.plot(
        key_sizes,
        encryption_times,
        marker="o",
        label="Encryption"
    )

    plt.plot(
        key_sizes,
        decryption_times,
        marker="o",
        label="Decryption"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Encryption and Decryption Performance")
    plt.legend()

    st.pyplot(fig2)

    plt.close(fig2)
    st.write("### Digital Signature and Verification Time")

    signing_times = [
        result["Signing"] for result in results
    ]

    verification_times = [
        result["Verification"] for result in results
    ]

    fig3 = plt.figure()

    plt.plot(
         key_sizes,
        signing_times,
        marker="o",
        label="Signing"
    )

    plt.plot(
        key_sizes,
         verification_times,
        marker="o",
        label="Verification"
    )

    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("RSA Digital Signature Performance")
    plt.legend()

    st.pyplot(fig3)

    plt.close(fig3)
    st.write("### 📌 Performance Interpretation")

    st.write(
        "The performance results show how the execution time of RSA operations "
        "changes with different key sizes. As the RSA key size increases, the "
        "computational work generally increases. Key generation may take more "
        "time because larger keys require the generation of larger prime numbers. "
        "The results provide a basic understanding of the relationship between "
        "RSA key size and computational performance."
    )
st.header("📌 Conclusion")

st.write(
    "This application demonstrates the basic working of the RSA cryptosystem "
    "with digital signatures using Python. It shows RSA key generation, "
    "encryption, decryption, digital signature generation, and signature "
    "verification. The performance analysis also helps to understand how "
    "different RSA key sizes affect the execution time of cryptographic "
    "operations. Thus, the application connects the mathematical concepts "
    "of RSA with their practical implementation."
)
st.header("🔄 Reset Application")

if st.button("Clear All"):

    st.session_state.signature = None
    st.session_state.public_key = None
    st.session_state.private_key = None
    st.session_state.ciphertext = None

    st.success("Application reset successfully!")
