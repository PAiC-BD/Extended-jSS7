/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

package org.restcomm.protocols.ss7.cap.gap;

import javolution.xml.XMLObjectReader;
import javolution.xml.XMLObjectWriter;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.cap.gap.GapOnServiceImpl;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 *
 * @author <a href="mailto:bartosz.krok@pro-ids.com"> Bartosz Krok (ProIDS sp. z o.o.)</a>
 *
 */
public class GapOnServiceTest {

    public static final int SERVICE_KEY = 821;

    public byte[] getData() {
        return new byte[] {48, 4, (byte) 128, 2, 3, 53};
    }

    public byte[] getDigitsData() {
        return new byte[] {48, 69, 91, 84};
    }

    @Test(groups = { "functional.decode", "gap" })
    public void testDecode() throws Exception {

        byte[] data = this.getData();
        AsnInputStream ais = new AsnInputStream(data);
        GapOnServiceImpl elem = new GapOnServiceImpl();
        int tag = ais.readTag();
        elem.decodeAll(ais);

        assertEquals(elem.getServiceKey(), SERVICE_KEY);
    }


    @Test(groups = { "functional.encode", "gap" })
    public void testEncode() throws Exception {

        GapOnServiceImpl elem = new GapOnServiceImpl(SERVICE_KEY);

        AsnOutputStream aos = new AsnOutputStream();
        elem.encodeAll(aos);

        assertTrue(Arrays.equals(aos.toByteArray(), this.getData()));
    }

    @Test(groups = { "functional.xml.serialize", "gap" })
    public void testXMLSerialize() throws Exception {

        GapOnServiceImpl original = new GapOnServiceImpl(SERVICE_KEY);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLObjectWriter writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for indentation).
        writer.write(original, "gapOnServiceArg", GapOnServiceImpl.class);
        writer.close();

        byte[] rawData = baos.toByteArray();
        String serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
        XMLObjectReader reader = XMLObjectReader.newInstance(bais);

        GapOnServiceImpl copy = reader.read("gapOnServiceArg", GapOnServiceImpl.class);

        assertTrue(isEqual(original, copy));
    }

    private boolean isEqual(GapOnServiceImpl o1, GapOnServiceImpl o2) {
        if (o1 == o2)
            return true;
        if (o1 == null && o2 != null || o1 != null && o2 == null)
            return false;
        if (o1 == null && o2 == null)
            return true;
        if (!o1.toString().equals(o2.toString()))
            return false;
        return true;
    }

}
