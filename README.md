# AES-GCM-Provider

A simple BoringSSL-backed JCE provider for Android projects that wish to have access to "incremental" AES-GCM primitives.

Conscrypt is now the default JCE provider for AES-GCM on Android, but it does not provide "incremental" AES-GCM. All calls
to `Cipher.update()` buffer the data in memory and don't return plaintext/ciphertext until `Cipher.doFinal()` is called,
at which point all buffered data is processed simultaneously. This is "safe," since it prevents the caller from accidentally
doing anything with unauthenticated plaintext, but it breaks the existing API, and can introduce crashes for software which was
previously processing large blobs, since the default provider now unexpectedly buffers the entire blob in memory.

# Using

`````
// Insert provider before Conscrypt
Security.insertProviderAt(new AesGcmProvider(), 1); 

// Construct a cipher and use as normal
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
...
`````

License
---------------------

Copyright 2019 Signal 

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
