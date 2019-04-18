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

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class ReserveBufferTest {

  @Test
  public void testIncremental() {
    ReserveBuffer buffer = new ReserveBuffer(16);
    byte[] input = new byte[1];

    for (int i=0;i<16;i++) {
      input[0] = (byte)i;
      byte[] result = buffer.update(input, 0, 1);
      assertEquals(0, result.length);
    }

    byte[] largeInput = new byte[16];
    Arrays.fill(largeInput, (byte)16);

    byte[] result = buffer.update(largeInput, 0, largeInput.length);
    assertEquals(16, result.length);

    for (int i=0;i<result.length;i++) {
      assertEquals(i, result[i]);
    }

    Arrays.fill(largeInput, (byte)17);

    result = buffer.update(largeInput, 0, largeInput.length);
    assertEquals(16, result.length);

    for (int i=0;i<result.length;i++) {
      assertEquals(16, result[i]);
    }
  }

  @Test
  public void testChunks() {
    ReserveBuffer buffer = new ReserveBuffer(16);

    byte[] input = new byte[32];
    for (int i=0;i<input.length;i++) {
      input[i] = (byte)i;
    }

    byte[] result = buffer.update(input, 0, input.length);
    assertEquals(16, result.length);

    for (int i=0;i<result.length;i++) {
      assertEquals(i, result[i]);
    }

  }

  @Test
  public void testTwoBlocks() throws IOException {
    ReserveBuffer buffer = new ReserveBuffer(16);
    byte[]        input  = new byte[32];

    for (int i=0;i<input.length;i++) {
      input[i] = (byte)i;
    }

    for(int i=0;i<16;i++) {
      byte[] output = buffer.update(input, i, 1);
      assertEquals(0, output.length);
    }

    ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();

    for (int i=16;i<input.length;i++) {
      byte[] output = buffer.update(input, i, 1);
      assertEquals(1, output.length);
      outputBuffer.write(output);
    }

    byte[] emitted = outputBuffer.toByteArray();
    assertEquals(16, emitted.length);

    for (int i=0;i<emitted.length;i++) {
      assertEquals(input[i], emitted[i]);
    }

    assertEquals(16, buffer.getAvailable());
    byte[] remainder = new byte[buffer.getAvailable()];
    buffer.read(remainder, 0, remainder.length);

    for (int i=0;i<remainder.length;i++) {
      assertEquals(input[16 + i], remainder[i]);
    }
  }

  @Test
  public void testTwoBlocksVariable() throws IOException {
    ReserveBuffer buffer = new ReserveBuffer(16);
    byte[]        input  = new byte[32];

    for (int j=1;j<input.length;j++) {

      for (int i=0;i<input.length;i++) {
        input[i] = (byte)i;
      }

      for(int i=0;i<16;i+=Math.min(j, 16-i)) {
        byte[] output = buffer.update(input, i, Math.min(j, 16-i));
        assertEquals(0, output.length);
      }

      ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();

      for (int i=16;i<input.length;i+=Math.min(j, input.length-i)) {
        byte[] output = buffer.update(input, i, Math.min(j, input.length-i));
        outputBuffer.write(output);
      }

      byte[] emitted = outputBuffer.toByteArray();
      assertEquals(16, emitted.length);

      for (int i=0;i<emitted.length;i++) {
        assertEquals(input[i], emitted[i]);
      }

      assertEquals(16, buffer.getAvailable());
      byte[] remainder = new byte[buffer.getAvailable()];
      buffer.read(remainder, 0, remainder.length);

      for (int i=0;i<remainder.length;i++) {
        assertEquals(input[16 + i], remainder[i]);
      }
    }
  }


}