/*
 * Copyright (C) 2019 Signal
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.signal.aesgcmprovider;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

public class AesGcmCipher extends CipherSpi {

  private GCMParameterSpec algorithmParameterSpec;
  private long             cipherContext;
  private boolean          encrypt;
  private ReserveBuffer    reserveBuffer;

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (!"GCM".equals(mode)) {
      throw new NoSuchAlgorithmException();
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    if (!"NoPadding".equals(padding)) {
      throw new NoSuchPaddingException();
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return 16;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    return inputLen + (algorithmParameterSpec.getTLen() / 8);
  }

  @Override
  protected byte[] engineGetIV() {
    return algorithmParameterSpec.getIV();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("GCM");
      parameters.init(algorithmParameterSpec);

      return parameters;
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidAlgorithmParameterException, InvalidKeyException {
    try {
      engineInit(opmode, key, params.getParameterSpec(GCMParameterSpec.class), random);
    } catch (InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException, InvalidKeyException {
    if (params == null && opmode == Cipher.DECRYPT_MODE) {
      throw new InvalidAlgorithmParameterException("Required GCMParameterSpec for decryption");
    } else if (params == null) {
      byte[] iv = new byte[12];
      random.nextBytes(iv);
      params = new GCMParameterSpec(128, iv);
    } else if (!(params instanceof GCMParameterSpec)) {
      throw new InvalidAlgorithmParameterException("Required GCMParameterSpec");
    }

    if (((GCMParameterSpec) params).getIV().length != 12) {
      throw new InvalidAlgorithmParameterException("Only IV of 12 is supported");
    }

    if (key.getEncoded().length != 16 && key.getEncoded().length != 32) {
      throw new InvalidAlgorithmParameterException("Only keys of 16 bytes or 32 bytes are supported");
    }

    this.algorithmParameterSpec = (GCMParameterSpec) params;
    this.encrypt                = opmode == Cipher.ENCRYPT_MODE;
    this.cipherContext          = initializeCipher(encrypt, key.getEncoded(), key.getEncoded().length, ((GCMParameterSpec) params).getIV());

    if (!encrypt) {
      this.reserveBuffer = new ReserveBuffer(((GCMParameterSpec) params).getTLen() / 8);
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    if (input == null) return new byte[0];

    if (encrypt) {
      byte[] output = new byte[inputLen];
      update(cipherContext, input, inputOffset, inputLen, output, 0, output.length);

      return output;
    } else {
      byte[] allocatedInput = reserveBuffer.update(input, inputOffset, inputLen);
      byte[] output = new byte[allocatedInput.length];
      update(cipherContext, allocatedInput, 0, allocatedInput.length, output, 0, output.length);

      return output;
    }
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    byte[] allocatedOutput = engineUpdate(input, inputOffset, inputLen);

    if (allocatedOutput.length > output.length - outputOffset) {
      throw new ShortBufferException("Needed: " + allocatedOutput.length + " but provided: " + (output.length - outputOffset));
    }

    System.arraycopy(allocatedOutput, 0, output, outputOffset, allocatedOutput.length);

    return allocatedOutput.length;
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws BadPaddingException, IllegalBlockSizeException {
    byte[] ciphertext = engineUpdate(input, inputOffset, inputLen);

    if (encrypt) {
      byte[] tag = new byte[algorithmParameterSpec.getTLen() / 8];
      finishEncrypt(cipherContext, tag, tag.length);

      byte[] combined = new byte[ciphertext.length + tag.length];
      System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
      System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

      return combined;
    } else {
      if (reserveBuffer.getAvailable() != (algorithmParameterSpec.getTLen() / 8)) {
        throw new BadPaddingException("Original ciphertext shorter than tag length");
      }

      byte[] tag = new byte[algorithmParameterSpec.getTLen() / 8];
      reserveBuffer.read(tag, 0, tag.length);

      if (!finishDecrypt(cipherContext, tag, tag.length)) {
        throw new BadPaddingException("Incorrect tag!");
      }

      return ciphertext;
    }
  }

  @Override
  protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws BadPaddingException, IllegalBlockSizeException, ShortBufferException {
    byte[] allocatedOutput = engineDoFinal(input, inputOffset, inputLen);

    if (allocatedOutput.length > output.length - outputOffset) {
      throw new ShortBufferException("Needed: " + allocatedOutput.length + " but provided: " + (output.length - outputOffset));
    }

    System.arraycopy(allocatedOutput, 0, output, outputOffset, allocatedOutput.length);
    return allocatedOutput.length;
  }

  @Override
  protected void engineUpdateAAD(byte[] src, int offset, int len) {
    updateAAD(cipherContext, src, offset, len);
  }

  @Override
  protected void engineUpdateAAD(ByteBuffer src) {
    if (src != null) {
      int aadLen = src.limit() - src.position();

      if (aadLen > 0) {
        if (src.hasArray()) {
          int aadOfs = addExact(src.arrayOffset(), src.position());
          updateAAD(cipherContext, src.array(), aadOfs, aadLen);
          src.position(src.limit());
        } else {
          byte[] aad = new byte[aadLen];
          src.get(aad);
          updateAAD(cipherContext, aad, 0, aadLen);
        }
      }
    }
  }

  private static int addExact(int x, int y) {
    int r = x + y;

    if (((x ^ r) & (y ^ r)) < 0) {
      throw new ArithmeticException("integer overflow");
    }

    return r;
  }

  @Override
  protected void finalize() {
    if (cipherContext != 0) {
      destroy(cipherContext);
    }
  }

  private native long initializeCipher(boolean encrypt, byte[] key, int keyLength, byte[] nonce);
  private native void updateAAD(long cipherContext, byte[] in, int offset, int length);
  private native void update(long cipherContext, byte[] in, int inputOffset, int length, byte[] out, int outputOffset, int outputLength);
  private native void finishEncrypt(long cipherContext, byte[] tagOut, int lengthInBytes);
  private native boolean finishDecrypt(long cipherContext, byte[] tagIn, int lengthInBytes);
  private native void destroy(long cipherContext);


}
