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

package org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javolution.xml.XMLObjectReader;
import javolution.xml.XMLObjectWriter;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TeleserviceCodeValue;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtTeleserviceCodeImpl;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class ExtTeleserviceCodeTest {

    byte[] data = new byte[] { 4, 1, 0x11 };
    byte[] dataEncoded = new byte[] { 0x11 };

    byte[] data2 = new byte[] { (byte) 131, 1, 16 };
    byte[] data3 = new byte[] { 4, 1, 34 };

    @Test(groups = { "functional.decode", "subscriberManagement" })
    public void testDecode() throws Exception {

        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        assertEquals(tag, Tag.STRING_OCTET);

        ExtTeleserviceCodeImpl impl = new ExtTeleserviceCodeImpl();
        impl.decodeAll(asn);

        assertTrue(Arrays.equals(impl.getData(), dataEncoded));
        assertEquals(impl.getTeleserviceCodeValue(), TeleserviceCodeValue.telephony);

        asn = new AsnInputStream(data2);
        tag = asn.readTag();
        assertEquals(tag, 3);

        impl = new ExtTeleserviceCodeImpl();
        impl.decodeAll(asn);

        assertEquals(impl.getTeleserviceCodeValue(), TeleserviceCodeValue.allSpeechTransmissionServices);

        asn = new AsnInputStream(data3);
        tag = asn.readTag();
        assertEquals(tag, Tag.STRING_OCTET);

        impl = new ExtTeleserviceCodeImpl();
        impl.decodeAll(asn);

        assertEquals(impl.getTeleserviceCodeValue(), TeleserviceCodeValue.shortMessageMO_PP);
    }

    @Test(groups = { "functional.encode", "subscriberManagement" })
    public void testEncode() throws Exception {

        ExtTeleserviceCodeImpl impl = new ExtTeleserviceCodeImpl(TeleserviceCodeValue.telephony);
        AsnOutputStream asnOS = new AsnOutputStream();
        impl.encodeAll(asnOS);
        byte[] encodedData = asnOS.toByteArray();
        byte[] rawData = data;
        assertTrue(Arrays.equals(rawData, encodedData));

        impl = new ExtTeleserviceCodeImpl(TeleserviceCodeValue.allSpeechTransmissionServices);
        asnOS = new AsnOutputStream();
        impl.encodeAll(asnOS, Tag.CLASS_CONTEXT_SPECIFIC, 3);
        encodedData = asnOS.toByteArray();
        rawData = data2;
        assertTrue(Arrays.equals(rawData, encodedData));

        impl = new ExtTeleserviceCodeImpl(TeleserviceCodeValue.shortMessageMO_PP);
        asnOS = new AsnOutputStream();
        impl.encodeAll(asnOS);
        encodedData = asnOS.toByteArray();
        rawData = data3;
        assertTrue(Arrays.equals(rawData, encodedData));
    }

    @Test(groups = { "functional.xml.serialize", "subscriberManagement" })
    public void testXMLSerializaion() throws Exception {
        ExtTeleserviceCodeImpl original = new ExtTeleserviceCodeImpl(TeleserviceCodeValue.telephony);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLObjectWriter writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "extTeleserviceCode", ExtTeleserviceCodeImpl.class);
        writer.close();

        byte[] rawData = baos.toByteArray();
        String serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
        XMLObjectReader reader = XMLObjectReader.newInstance(bais);
        ExtTeleserviceCodeImpl copy = reader.read("extTeleserviceCode", ExtTeleserviceCodeImpl.class);

        assertEquals(copy.getTeleserviceCodeValue(), original.getTeleserviceCodeValue());
    }

}
