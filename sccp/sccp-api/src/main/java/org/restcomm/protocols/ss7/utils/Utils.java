/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

/**
 * The Java Call Control API for CAMEL 2
 *
 * The source code contained in this file is in in the public domain.
 * It can be used in any project or product without prior permission,
 * license or royalty payments. There is  NO WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR STATUTORY, INCLUDING, WITHOUT LIMITATION,
 * THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * AND DATA ACCURACY.  We do not warrant or make any representations
 * regarding the use of the software or the  results thereof, including
 * but not limited to the correctness, accuracy, reliability or
 * usefulness of the software.
 */
package org.restcomm.protocols.ss7.utils;


/**
 * This class contains various static utility methods.
 *
 * @author Oleg Kulikov
 *
 */
public class Utils {
    /**
     * Construct a String containing a hex-dump of a byte array
     *
     * @param bytes the data to dump
     * @return a string containing the hexdump
     */
    public static String hexDump(byte[] bytes) {
        return hexDump(null, bytes);
    }

    /**
     * Construct a String containing a hex-dump of a byte array
     *
     * @param label the label of the hexdump or null
     * @param bytes the data to dump
     * @return a string containing the hexdump
     */
    public static String hexDump(String label, byte[] bytes) {
        final int modulo = 16;
        final int brk = modulo / 2;
        int indent = (label == null) ? 0 : label.length();

        StringBuffer sb = new StringBuffer(indent + 1);

        while (indent > 0) {
            sb.append(" ");
            indent--;
        }

        String ind = sb.toString();

        if (bytes == null) {
            return null;
        }

        sb = new StringBuffer(bytes.length * 4);

        StringBuffer cb = new StringBuffer(16);
        boolean nl = true;
        int i = 0;

        for (i = 1; i <= bytes.length; i++) {
            // start of line?
            if (nl) {
                nl = false;

                if (i > 1) {
                    sb.append(ind);
                } else if (label != null) {
                    sb.append(label);
                }

                String ha = Integer.toHexString(i - 1);

                for (int j = ha.length(); j <= 8; j++) {
                    sb.append("0");
                }

                sb.append(ha).append(" ");
            }

            sb.append(" ");

            int c = (bytes[i - 1] & 0xFF);
            String hx = Integer.toHexString(c).toUpperCase();

            if (hx.length() == 1) {
                sb.append("0");
            }

            sb.append(hx);
            cb.append((c < 0x21 || c > 0x7e) ? '.' : (char) (c));

            if ((i % brk) == 0) {
                sb.append(" ");
            }

            if ((i % modulo) == 0) {
                sb.append("|").append(cb).append("|\n");
                nl = true;
                cb = new StringBuffer(16);
            }
        }

        int mod = i % modulo;

        if (mod != 1) {
            // Fill the rest of the line
            while (mod <= modulo) {
                sb.append("   ");

                if ((mod % brk) == 0) {
                    sb.append(" ");
                }

                mod++;
            }

            sb.append("|").append(cb).append("|\n");
        }

        return sb.toString();
    }
}
