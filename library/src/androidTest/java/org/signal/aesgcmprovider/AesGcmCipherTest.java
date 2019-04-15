package org.signal.aesgcmprovider;

import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class AesGcmCipherTest {

  private static final String[] VECTORS = new String[] {
      "00000000000000000000000000000000:000000000000000000000000::::58e2fccefa7e3061367f1d57a4e7455a",
      "00000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78::ab6e47d42cec13bdf53a67b21257bddf",
      "feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985::4d5c2af327cd64a62cf35abd2ba6fab4",
      "feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091:feedfacedeadbeeffeedfacedeadbeefabaddad2:5bc94fbc3221a5db94fae95ae7121a47",
      "feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598:feedfacedeadbeeffeedfacedeadbeefabaddad2:3612d2e79e3b0785561be14aaca2fccb",
      "feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5:feedfacedeadbeeffeedfacedeadbeefabaddad2:619cc5aefffe0bfa462af43c1699d050",
      "0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000::::530f8afbc74536b9a963b4f1c4cb738b",
      "0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:cea7403d4d606b6e074ec5d3baf39d18::d0d1c8a799996bf0265b98b5d48ab919",
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad::b094dac5d93471bdec1a502270e3cc6c",
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662:feedfacedeadbeeffeedfacedeadbeefabaddad2:76fc6ece0f4e1768cddf8853bb2d551b",
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f:feedfacedeadbeeffeedfacedeadbeefabaddad2:3a337dbf46a792c45e454913fe2ea8f2",
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f:feedfacedeadbeeffeedfacedeadbeefabaddad2:a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
      "00000000000000000000000000000000:000000000000000000000000:::d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad:5fea793a2d6f974d37e68e0cb8ff9492",
      "00000000000000000000000000000000:000000000000000000000000:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0::9dd0a376b08e40eb00c35f29f9ea61a4",
      "00000000000000000000000000000000:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d5270291::98885a3a22bd4742fe7b72172193b163",
      "00000000000000000000000000000000:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d527029195b84d1b96c690ff2f2de30bf2ec89e00253786e126504f0dab90c48a30321de3345e6b0461e7c9e6c6b7afedde83f40::cac45f60e31efd3b5a43b98a22ce1aa1",
      "00000000000000000000000000000000:ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:56b3373ca9ef6e4a2b64fe1e9a17b61425f10d47a75a5fce13efc6bc784af24f4141bdd48cf7c770887afd573cca5418a9aeffcd7c5ceddfc6a78397b9a85b499da558257267caab2ad0b23ca476a53cb17fb41c4b8b475cb4f3f7165094c229c9e8c4dc0a2a5ff1903e501511221376a1cdb8364c5061a20cae74bc4acd76ceb0abc9fd3217ef9f8c90be402ddf6d8697f4f880dff15bfb7a6b28241ec8fe183c2d59e3f9dfff653c7126f0acb9e64211f42bae12af462b1070bef1ab5e3606::566f8ef683078bfdeeffa869d751a017",
      "843ffcf5d2b72694d19ed01d01249412:dbcca32ebf9b804617c3aa9e:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f:6268c6fa2a80b2d137467f092f657ac04d89be2beaa623d61b5a868c8f03ff95d3dcee23ad2f1ab3a6c80eaf4b140eb05de3457f0fbc111a6b43d0763aa422a3013cf1dc37fe417d1fbfc449b75d4cc5:00000000000000000000000000000000101112131415161718191a1b1c1d1e1f:3b629ccfbc1119b7319e1dce2cd6fd6d"
  };

  static {
    System.loadLibrary("aesgcm");
  }

  @Before
  public void setup() {
    Security.insertProviderAt(new AesGcmProvider(), 1);
  }

  @Test
  public void testProvider() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "AES"));
    assertEquals("AesGcmProvider", cipher.getProvider().getName());
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");

    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);

    byte[] iv = new byte[12];

    encryptCipher.init(Cipher.ENCRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    byte[] original = new byte[128];
    Arrays.fill(original, (byte)0x0a);

    byte[] ciphertext = encryptCipher.doFinal(original);
    assertEquals(original.length + 16, ciphertext.length);

    assertArrayEquals(encryptCipher.getIV(), iv);

    Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
    decryptCipher.init(Cipher.DECRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    assertArrayEquals(decryptCipher.getIV(), iv);

    byte[] plaintext = decryptCipher.doFinal(ciphertext);
    assertEquals(original.length, plaintext.length);
    assertArrayEquals(plaintext, original);
  }

  @Test
  public void testEncryptDecryptWithAad() throws Exception {
    Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");

    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);

    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);

    encryptCipher.init(Cipher.ENCRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    byte[] original = new byte[128];
    byte[] aad      = new byte[37];
    Arrays.fill(original, (byte)0x0a);
    Arrays.fill(aad, (byte)0x0c);

    encryptCipher.updateAAD(aad);
    byte[] ciphertext = encryptCipher.doFinal(original);
    assertEquals(original.length + 16, ciphertext.length);

    Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
    decryptCipher.init(Cipher.DECRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    decryptCipher.updateAAD(aad);
    byte[] plaintext = decryptCipher.doFinal(ciphertext);
    assertArrayEquals(plaintext, original);
  }

  @Test
  public void testEncryptDecryptWithBadAad() throws Exception {
    Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");

    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);

    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);

    encryptCipher.init(Cipher.ENCRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    byte[] original = new byte[128];
    byte[] aad      = new byte[37];
    Arrays.fill(original, (byte)0x0a);
    Arrays.fill(aad, (byte)0x0c);

    encryptCipher.updateAAD(aad);
    byte[] ciphertext = encryptCipher.doFinal(original);
    assertEquals(original.length + 16, ciphertext.length);

    Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
    decryptCipher.init(Cipher.DECRYPT_MODE,
                       new SecretKeySpec(key, "AES"),
                       new GCMParameterSpec(128, iv));

    try {
      decryptCipher.doFinal(ciphertext);
      throw new AssertionError("Should have failed");
    } catch (BadPaddingException e) {
      // good
    }
  }

  @Test
  public void testVectors() throws Exception {
    for (String vector : VECTORS) {
      String[] parts      = vector.split(":");
      byte[]   key        = Hex.fromStringCondensed(parts[0]);
      byte[]   iv         = Hex.fromStringCondensed(parts[1]);
      byte[]   plaintext  = Hex.fromStringCondensed(parts[2]);
      byte[]   ciphertext = Hex.fromStringCondensed(parts[3]);
      byte[]   aad        = Hex.fromStringCondensed(parts[4]);
      byte[]   tag        = Hex.fromStringCondensed(parts[5]);


      Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
      assertEquals(encryptCipher.getProvider().getName(), "AesGcmProvider");

      encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tag.length * 8, iv));
      encryptCipher.updateAAD(aad);

      byte[] ciphertextParts  = encryptCipher.doFinal(plaintext);
      byte[] ciphertextOutput = new byte[ciphertextParts.length - tag.length];
      byte[] tagOutput        = new byte[tag.length];
      System.arraycopy(ciphertextParts, 0, ciphertextOutput, 0, ciphertextOutput.length);
      System.arraycopy(ciphertextParts, ciphertextOutput.length, tagOutput,0, tagOutput.length);

      assertArrayEquals(ciphertext, ciphertextOutput);
      assertArrayEquals(tag, tagOutput);

      Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
      assertEquals(decryptCipher.getProvider().getName(), "AesGcmProvider");

      decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tag.length * 8, iv));
      decryptCipher.updateAAD(aad);

      byte[] plaintextOutput = decryptCipher.doFinal(ciphertextParts);
      assertArrayEquals(plaintext, plaintextOutput);
    }
  }

  @Test
  public void testVectorsIncremental() throws Exception {
    for (String vector : VECTORS) {
      String[] parts      = vector.split(":");
      byte[]   key        = Hex.fromStringCondensed(parts[0]);
      byte[]   iv         = Hex.fromStringCondensed(parts[1]);
      byte[]   plaintext  = Hex.fromStringCondensed(parts[2]);
      byte[]   ciphertext = Hex.fromStringCondensed(parts[3]);
      byte[]   aad        = Hex.fromStringCondensed(parts[4]);
      byte[]   tag        = Hex.fromStringCondensed(parts[5]);


      for (int i=1;i<plaintext.length;i++) {
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        assertEquals(encryptCipher.getProvider().getName(), "AesGcmProvider");

        encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tag.length * 8, iv));
        int aadLengthRemaining = aad.length;

        while (aadLengthRemaining > 0) {
          encryptCipher.updateAAD(aad, aad.length - aadLengthRemaining, Math.min(aadLengthRemaining, i));
          aadLengthRemaining -= Math.min(aadLengthRemaining, i);
        }

        ByteArrayOutputStream ciphertextPartsStream    = new ByteArrayOutputStream();
        int                   plaintextLengthRemaining = plaintext.length;

        while (plaintextLengthRemaining > 0) {
          byte[] incrementalOutput = encryptCipher.update(plaintext, plaintext.length - plaintextLengthRemaining, Math.min(plaintextLengthRemaining, i));

          if (incrementalOutput != null) ciphertextPartsStream.write(incrementalOutput);
          plaintextLengthRemaining -= Math.min(plaintextLengthRemaining, i);
        }

        ciphertextPartsStream.write(encryptCipher.doFinal());

        byte[] ciphertextParts = ciphertextPartsStream.toByteArray();
        byte[] ciphertextOutput = new byte[ciphertextParts.length - tag.length];
        byte[] tagOutput = new byte[tag.length];
        System.arraycopy(ciphertextParts, 0, ciphertextOutput, 0, ciphertextOutput.length);
        System.arraycopy(ciphertextParts, ciphertextOutput.length, tagOutput, 0, tagOutput.length);

        assertArrayEquals(ciphertext, ciphertextOutput);
        assertArrayEquals(tag, tagOutput);

        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        assertEquals(decryptCipher.getProvider().getName(), "AesGcmProvider");

        decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tag.length * 8, iv));

        aadLengthRemaining = aad.length;

        while (aadLengthRemaining > 0) {
          decryptCipher.updateAAD(aad, aad.length - aadLengthRemaining, Math.min(aadLengthRemaining, i));
          aadLengthRemaining -= Math.min(aadLengthRemaining, i);
        }

        ByteArrayOutputStream plaintextOutputStream     = new ByteArrayOutputStream();
        int                   ciphertextLengthRemaining = ciphertextParts.length;

        while (ciphertextLengthRemaining > 0) {
          byte[] incrementalOutput = decryptCipher.update(ciphertextParts, ciphertextParts.length - ciphertextLengthRemaining, Math.min(ciphertextLengthRemaining, i));

          if (incrementalOutput != null) {
            plaintextOutputStream.write(incrementalOutput);
          }

          ciphertextLengthRemaining -= Math.min(i, ciphertextLengthRemaining);
        }

        plaintextOutputStream.write(decryptCipher.doFinal());

        assertArrayEquals(plaintext, plaintextOutputStream.toByteArray());
        Log.w("AesGcmcipherTest", "Passed: " + i);
      }
    }
  }



}
