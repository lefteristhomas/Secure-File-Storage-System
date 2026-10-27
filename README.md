# Secure File Storage System

A Python command-line application that demonstrates how authentication, encryption, digital signatures, and nonce tracking can work together in a local file storage workflow.

Users can register with a one-time registration code, log in, store encrypted files, and retrieve them after ownership and cryptographic verification. The application runs locally and uses JSON files for persistent records. Its interactive prompts are currently in Greek.

## Security Mechanisms

### Password Hashing with PBKDF2 and Salt

Passwords are processed using **PBKDF2-HMAC-SHA256**, with **100,000 iterations** and a **32-byte output**. Each password receives a randomly generated **16-byte salt**.

The salt ensures that identical passwords do not produce identical stored hashes. PBKDF2 repeats the hashing process to increase the computational cost of password guessing.

The application stores the derived hash and salt rather than the original password. During login, it repeats the calculation with the saved salt and compares the results using `secrets.compare_digest()`, which provides a constant-time comparison.

### One-Time Registration Codes

The registration process requires an **8-character hexadecimal code** generated using Python's `secrets` module and associated with a specific username.

The application checks that the code matches and has not already been used. A matching code is marked as used before account creation continues.

This is a registration approval mechanism, not a time-based OTP system or a second factor required during login. Although the issuance time is recorded, code expiration is not enforced.

### AES-256-GCM File Encryption

Each uploaded file is encrypted using **AES-256-GCM**, with a new random **256-bit key** and a **12-byte encryption nonce**.

AES protects the file's contents, while GCM adds an authentication tag that is checked during decryption. If the encrypted data has been modified or the key or nonce is incorrect, authentication fails and the file is not recovered.

The encrypted content is saved as a `.enc` file.

### RSA Digital Signatures

Registration creates an **RSA-2048 key pair** for each user.

Before encryption, the application signs the original file contents together with an operation nonce using **RSA-PSS with SHA-256**. The private key creates the signature, and the corresponding public key verifies it after decryption.

This verification checks that the recovered contents and signed nonce match the signature created with the user's private key. The decrypted file is written to disk only after verification succeeds.

### Nonce Tracking

The application generates a separate random **16-byte operation nonce** for each upload and records it in `nonces.json`. If the same value has already been recorded, the upload is rejected.

This operation nonce is included in the digital signature and is distinct from the nonce used by AES-GCM.

The mechanism demonstrates duplicate nonce detection during uploads. It does not implement a complete replay-protected communication protocol.

### Authentication and Ownership Checks

Uploading and downloading require a successful login through the CLI.

During retrieval, the application compares the logged-in username with the uploader recorded in the file's metadata. If they differ, access is denied.

Failed login attempts display the same message for an unknown username and an incorrect password.

## File Storage Workflow

### Registration and Login

1. Generate a registration code for a username through the administrative menu option.
2. Register with the username, code, and password.
3. The application stores the password hash and salt, then generates the user's RSA keys.
4. Log in to access upload and download operations.

### Uploading a File

1. Read the selected file.
2. Generate an operation nonce.
3. Sign the original contents and nonce using the user's RSA private key.
4. Check and record the operation nonce.
5. Encrypt the contents using a fresh AES key and encryption nonce.
6. Save the encrypted file and its JSON metadata.

The metadata contains the original filename, uploader, operation nonce, AES nonce, AES key, digital signature, and timestamp. Binary values are represented using Base64.

### Retrieving a File

1. Load the metadata and check ownership.
2. Read the encrypted contents.
3. Decode the stored cryptographic values.
4. Decrypt the file and validate the GCM authentication tag.
5. Verify the RSA signature over the recovered contents and operation nonce.
6. Save the result as `downloaded_<original_filename>`.

## Local Data Organization

- `users.json` — usernames, password hashes, salts, and account creation timestamps.
- `otp_store.json` — registration codes, issuance timestamps, and usage status.
- `nonces.json` — operation nonces recorded during uploads.
- `keys/` — users' RSA public and private keys in PEM format.
- `secure_storage/` — encrypted files and their accompanying JSON metadata.

These files and directories are created automatically when the application starts.

## Scope and Limitations

This is an educational implementation that demonstrates cryptographic operations and their integration into a file storage workflow.

- **Key protection:** AES keys are stored alongside encrypted files in metadata, and RSA private keys are saved without encryption. Base64 is an encoding format, not encryption. Anyone who can read these local files may recover file contents or use private keys.
- **Administrative access:** the option labeled “Admin” is available directly from the menu without administrator authentication.
- **Registration and login:** registration codes have no enforced expiration, and neither code verification nor login has attempt limits.
- **Local access controls:** ownership checks operate within the application and rely on editable JSON metadata. They do not protect against someone with direct filesystem access.
- **Storage behavior:** files with the same original filename share the same storage paths, so a later upload can overwrite an earlier one, including an upload from another user.
- **Input and persistence:** the application does not implement comprehensive path validation, atomic database updates, or file locking for concurrent use.

Runtime data such as private keys, account records, registration codes, and stored file metadata should remain outside the public source repository.
