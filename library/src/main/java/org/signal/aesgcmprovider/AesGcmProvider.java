package org.signal.aesgcmprovider;

import java.security.Provider;

public final class AesGcmProvider extends Provider {

  public AesGcmProvider() {
    super("AesGcmProvider", 1.0, "AES GCM BoringSSL-backed provider to work around decisions made by Conscrypt");
    put("Cipher.AES/GCM/NoPadding", "org.signal.aesgcmprovider.AesGcmCipher");
  }



}
