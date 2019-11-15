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

package org.restcomm.protocols.ss7.map.service.mobility.locationManagement;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SuperChargerInfoImpl;
import org.testng.annotations.Test;

public class SuperChargerInfoTest {

    private byte[] getEncodedData1() {
        return new byte[] { (byte) 128, 0 };
    }

    private byte[] getEncodedData2() {
        return new byte[] { (byte) 129, 1, 5 };
    }

    @Test
    public void testDecode() throws Exception {

        byte[] rawData = getEncodedData1();
        AsnInputStream asn = new AsnInputStream(rawData);

        int tag = asn.readTag();
        SuperChargerInfoImpl asc = new SuperChargerInfoImpl();
        asc.decodeAll(asn);

        assertEquals(tag, SuperChargerInfoImpl._ID_sendSubscriberData);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertTrue(asc.getSendSubscriberData());
        assertNull(asc.getSubscriberDataStored());

        rawData = getEncodedData2();
        asn = new AsnInputStream(rawData);

        tag = asn.readTag();
        asc = new SuperChargerInfoImpl();
        asc.decodeAll(asn);

        assertEquals(tag, SuperChargerInfoImpl._ID_subscriberDataStored);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertNull(asc.getSendSubscriberData());
        assertEquals(asc.getSubscriberDataStored().length, 1);
        assertEquals(asc.getSubscriberDataStored()[0], 5);
    }

    @Test(groups = { "functional.encode" })
    public void testEncode() throws Exception {

        SuperChargerInfoImpl asc = new SuperChargerInfoImpl(true);

        AsnOutputStream asnOS = new AsnOutputStream();
        asc.encodeAll(asnOS);

        byte[] encodedData = asnOS.toByteArray();
        byte[] rawData = getEncodedData1();
        assertTrue(Arrays.equals(rawData, encodedData));

        asc = new SuperChargerInfoImpl(new byte[] { 5 });

        asnOS = new AsnOutputStream();
        asc.encodeAll(asnOS);

        encodedData = asnOS.toByteArray();
        rawData = getEncodedData2();
        assertTrue(Arrays.equals(rawData, encodedData));

    }

}
