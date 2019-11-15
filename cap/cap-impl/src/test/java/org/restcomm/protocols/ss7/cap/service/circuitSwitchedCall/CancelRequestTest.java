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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javolution.xml.XMLObjectReader;
import javolution.xml.XMLObjectWriter;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.CancelRequestImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.CallSegmentToCancelImpl;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 * @author Amit Bhayani
 *
 */
public class CancelRequestTest {

    public byte[] getData1() {
        return new byte[] { (byte) 128, 2, 42, (byte) 248 };
    }

    public byte[] getData2() {
        return new byte[] { (byte) 129, 0 };
    }

    public byte[] getData3() {
        return new byte[] { (byte) 162, 3, (byte) 129, 1, 20 };
    }

    @Test(groups = { "functional.decode", "circuitSwitchedCall" })
    public void testDecode() throws Exception {

        byte[] data = this.getData1();
        AsnInputStream ais = new AsnInputStream(data);
        CancelRequestImpl elem = new CancelRequestImpl();
        int tag = ais.readTag();
        assertEquals(tag, 0);
        elem.decodeAll(ais);
        assertEquals((int) elem.getInvokeID(), 11000);
        assertFalse(elem.getAllRequests());
        assertNull(elem.getCallSegmentToCancel());

        data = this.getData2();
        ais = new AsnInputStream(data);
        elem = new CancelRequestImpl();
        tag = ais.readTag();
        assertEquals(tag, 1);
        elem.decodeAll(ais);
        assertNull(elem.getInvokeID());
        assertTrue(elem.getAllRequests());
        assertNull(elem.getCallSegmentToCancel());

        data = this.getData3();
        ais = new AsnInputStream(data);
        elem = new CancelRequestImpl();
        tag = ais.readTag();
        assertEquals(tag, 2);
        elem.decodeAll(ais);
        assertNull(elem.getInvokeID());
        assertFalse(elem.getAllRequests());
        assertNull(elem.getCallSegmentToCancel().getInvokeID());
        assertEquals((int) elem.getCallSegmentToCancel().getCallSegmentID(), 20);
    }

    @Test(groups = { "functional.encode", "circuitSwitchedCall" })
    public void testEncode() throws Exception {

        CancelRequestImpl elem = new CancelRequestImpl(11000);
        AsnOutputStream aos = new AsnOutputStream();
        elem.encodeAll(aos);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData1()));

        elem = new CancelRequestImpl(true);
        aos = new AsnOutputStream();
        elem.encodeAll(aos);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData2()));

        CallSegmentToCancelImpl callSegmentToCancel = new CallSegmentToCancelImpl(null, 20);
        // Integer invokeID, Integer callSegmentID
        elem = new CancelRequestImpl(callSegmentToCancel);
        aos = new AsnOutputStream();
        elem.encodeAll(aos);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData3()));
    }

    @Test(groups = { "functional.xml.serialize", "circuitSwitchedCall" })
    public void testXMLSerializaion() throws Exception {
        CancelRequestImpl original = new CancelRequestImpl(11000);
        original.setInvokeId(24);

        // Writes the area to a file.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLObjectWriter writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "cancelRequest", CancelRequestImpl.class);
        writer.close();

        byte[] rawData = baos.toByteArray();
        String serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
        XMLObjectReader reader = XMLObjectReader.newInstance(bais);
        CancelRequestImpl copy = reader.read("cancelRequest", CancelRequestImpl.class);

        assertEquals(copy.getInvokeId(), original.getInvokeId());
        assertEquals(copy.getInvokeID(), original.getInvokeID());
        assertEquals(copy.getAllRequests(), original.getAllRequests());
        original.setInvokeId(24);

        CallSegmentToCancelImpl callSegmentToCancel = new CallSegmentToCancelImpl(null, 20);
        // Integer invokeID, Integer callSegmentID
        original = new CancelRequestImpl(callSegmentToCancel);

        // Writes the area to a file.
        baos = new ByteArrayOutputStream();
        writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "cancelRequest", CancelRequestImpl.class);
        writer.close();

        rawData = baos.toByteArray();
        serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        bais = new ByteArrayInputStream(rawData);
        reader = XMLObjectReader.newInstance(bais);
        copy = reader.read("cancelRequest", CancelRequestImpl.class);

        assertEquals(copy.getInvokeId(), original.getInvokeId());
        assertEquals(copy.getAllRequests(), original.getAllRequests());
        assertEquals(copy.getCallSegmentToCancel().getCallSegmentID(), original.getCallSegmentToCancel().getCallSegmentID());

        original = new CancelRequestImpl(true);

        // Writes the area to a file.
        baos = new ByteArrayOutputStream();
        writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "cancelRequest", CancelRequestImpl.class);
        writer.close();

        rawData = baos.toByteArray();
        serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        bais = new ByteArrayInputStream(rawData);
        reader = XMLObjectReader.newInstance(bais);
        copy = reader.read("cancelRequest", CancelRequestImpl.class);

        assertEquals(copy.getInvokeId(), original.getInvokeId());
        assertEquals(copy.getAllRequests(), original.getAllRequests());
    }
}
