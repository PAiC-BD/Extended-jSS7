/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
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

package org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement;

/**
*
<code>
Maximum bit rate for downlink (extended), octet 15
Bits
8 7 6 5 4 3 2 1
In MS to network direction and in network to MS direction:
0 0 0 0 0 0 0 0 Use the value indicated by the Maximum bit rate for downlink in octet 9.

                    For all other values: Ignore the value indicated by the Maximum bit rate for downlink in octet 9
                    and use the following value:
0 0 0 0 0 0 0 1 The maximum bit rate is 8600 kbps + ((the binary coded value in 8 bits) * 100 kbps),
0 1 0 0 1 0 1 0 giving a range of values from 8700 kbps to 16000 kbps in 100 kbps increments.

0 1 0 0 1 0 1 1 The maximum bit rate is 16 Mbps + ((the binary coded value in 8 bits - 01001010) * 1 Mbps),
1 0 1 1 1 0 1 0 giving a range of values from 17 Mbps to 128 Mbps in 1 Mbps increments.

1 0 1 1 1 0 1 1 The maximum bit rate is 128 Mbps + ((the binary coded value in 8 bits - 10111010) * 2 Mbps),
1 1 1 1 1 0 1 0 giving a range of values from 130 Mbps to 256 Mbps in 2 Mbps increments.

The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol.

The MS shall map all other values not explicitly defined onto the maximum value defined in this version of the protocol.
</code>
*
* @author sergey vetyutnev
*
*/
public interface ExtQoSSubscribed_BitRateExtended {

    int getSourceData();

    boolean isUseNonextendedValue();

    /**
     * @return BitRate (kbit/s) value or 0 when source==0 or not specified in
     *         23.107
     */
    int getBitRate();

}
