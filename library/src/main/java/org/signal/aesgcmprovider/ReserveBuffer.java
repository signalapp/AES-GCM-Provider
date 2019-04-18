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

class ReserveBuffer {
  private final byte[] reserve;
  private       int    writePointer = 0;
  private       int    available    = 0;

  ReserveBuffer(int sizeInBytes) {
    this.reserve = new byte[sizeInBytes];
  }

  public byte[] update(byte[] input, int offset, int inputLength) {
    int    reserveToApply   = Math.min(reserve.length, inputLength);
    int    reserveToRelease = Math.max(reserveToApply - capacity(), 0);
    byte[] output           = new byte[reserveToRelease + (inputLength - reserveToApply)];

    read(output, 0, reserveToRelease);
    System.arraycopy(input, offset, output, reserveToRelease, inputLength - reserveToApply);
    write(input, offset + (inputLength - reserveToApply), reserveToApply);

    return output;
  }

  private void write(byte[] buffer, int offset, int length) {
    int remainingToEnd = reserve.length - writePointer;
    int amountToCopy   = Math.min(remainingToEnd, length);

    System.arraycopy(buffer, offset, reserve, writePointer, amountToCopy);
    System.arraycopy(buffer, offset+amountToCopy, reserve, 0, length-amountToCopy);

    writePointer = (writePointer + length) % reserve.length;
    available   += length;
  }

  public void read(byte[] buffer, int offset, int length) {
    int startPosition = writePointer - available;

    if (startPosition < 0) {
      startPosition += reserve.length;
    }

    int remainingToEnd = reserve.length - startPosition;
    int amountToCopy   = Math.min(remainingToEnd, length);

    System.arraycopy(reserve, startPosition, buffer, offset, amountToCopy);
    System.arraycopy(reserve, 0, buffer, offset + amountToCopy, length - amountToCopy);

    available -= length;
  }

  public int capacity() {
    return reserve.length - available;
  }

  public int getAvailable() {
    return available;
  }

}
