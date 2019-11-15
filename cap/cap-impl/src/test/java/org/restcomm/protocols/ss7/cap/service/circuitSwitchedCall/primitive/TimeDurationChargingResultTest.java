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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive;

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
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.primitives.AChChargingAddress;
import org.restcomm.protocols.ss7.cap.api.primitives.ReceivingSideID;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.TimeInformation;
import org.restcomm.protocols.ss7.cap.primitives.AChChargingAddressImpl;
import org.restcomm.protocols.ss7.cap.primitives.CAPExtensionsTest;
import org.restcomm.protocols.ss7.cap.primitives.ReceivingSideIDImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.TimeDurationChargingResultImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.TimeInformationImpl;
import org.restcomm.protocols.ss7.inap.api.primitives.LegType;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 * @author Amit Bhayani
 *
 */
public class TimeDurationChargingResultTest {

    public byte[] getData1() {
        return new byte[] { (byte) 160, 13, (byte) 160, 3, (byte) 129, 1, 1, (byte) 161, 3, (byte) 128, 1, 26, (byte) 130, 1, 0 };
    }

    public byte[] getData2() {
        return new byte[] { (byte) 160, 32, (byte) 160, 3, (byte) 129, 1, 2, (byte) 161, 3, (byte) 128, 1, 55, (byte) 131, 0,
                (byte) 164, 18, 48, 5, 2, 1, 2, (byte) 129, 0, 48, 9, 2, 1, 3, 10, 1, 1, (byte) 129, 1, (byte) 255 };
    }

    public byte[] getData3() {
        return new byte[] { (byte) 160, 19, (byte) 160, 3, (byte) 129, 1, 2, (byte) 161, 3, (byte) 128, 1, 55, (byte) 130, 1, 0, (byte) 165, 4, (byte) 159, 50,
                1, 13 };
    }

    @Test(groups = { "functional.decode", "circuitSwitchedCall.primitive" })
    public void testDecode() throws Exception {

        byte[] data = this.getData1();
        AsnInputStream ais = new AsnInputStream(data);
        TimeDurationChargingResultImpl elem = new TimeDurationChargingResultImpl();
        int tag = ais.readTag();
        elem.decodeAll(ais);
        assertEquals(elem.getPartyToCharge().getReceivingSideID(), LegType.leg1);
        assertEquals((int) elem.getTimeInformation().getTimeIfNoTariffSwitch(), 26);
        assertFalse(elem.getLegActive());
        assertFalse(elem.getCallLegReleasedAtTcpExpiry());
        assertNull(elem.getExtensions());
        assertNull(elem.getAChChargingAddress());


        data = this.getData2();
        ais = new AsnInputStream(data);
        elem = new TimeDurationChargingResultImpl();
        tag = ais.readTag();
        elem.decodeAll(ais);
        assertEquals(elem.getPartyToCharge().getReceivingSideID(), LegType.leg2);
        assertEquals((int) elem.getTimeInformation().getTimeIfNoTariffSwitch(), 55);
        assertTrue(elem.getLegActive());
        assertTrue(elem.getCallLegReleasedAtTcpExpiry());
        assertTrue(CAPExtensionsTest.checkTestCAPExtensions(elem.getExtensions()));
        assertNull(elem.getAChChargingAddress());


        data = this.getData3();
        ais = new AsnInputStream(data);
        elem = new TimeDurationChargingResultImpl();
        tag = ais.readTag();
        elem.decodeAll(ais);
        assertEquals(elem.getPartyToCharge().getReceivingSideID(), LegType.leg2);
        assertEquals((int) elem.getTimeInformation().getTimeIfNoTariffSwitch(), 55);
        assertFalse(elem.getLegActive());
        assertFalse(elem.getCallLegReleasedAtTcpExpiry());
        assertNull(elem.getExtensions());
        assertEquals(elem.getAChChargingAddress().getSrfConnection(), 13);
    }

    @Test(groups = { "functional.encode", "circuitSwitchedCall.primitive" })
    public void testEncode() throws Exception {

        ReceivingSideID partyToCharge = new ReceivingSideIDImpl(LegType.leg1);
        TimeInformation ti = new TimeInformationImpl(26);
        TimeDurationChargingResultImpl elem = new TimeDurationChargingResultImpl(partyToCharge, ti, false, false, null, null);
        // ReceivingSideID partyToCharge, TimeInformation timeInformation,
        // boolean legActive,
        // boolean callLegReleasedAtTcpExpiry, CAPExtensions extensions,
        // AChChargingAddress aChChargingAddress
        AsnOutputStream aos = new AsnOutputStream();
        elem.encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, 0);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData1()));


        partyToCharge = new ReceivingSideIDImpl(LegType.leg2);
        ti = new TimeInformationImpl(55);
        elem = new TimeDurationChargingResultImpl(partyToCharge, ti, true, true, CAPExtensionsTest.createTestCAPExtensions(),
                null);
        // ReceivingSideID partyToCharge, TimeInformation timeInformation,
        // boolean legActive,
        // boolean callLegReleasedAtTcpExpiry, CAPExtensions extensions,
        // AChChargingAddress aChChargingAddress
        aos = new AsnOutputStream();
        elem.encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, 0);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData2()));


        AChChargingAddress aChChargingAddress = new AChChargingAddressImpl(13);
        elem = new TimeDurationChargingResultImpl(partyToCharge, ti, false, false, null, aChChargingAddress);
        aos = new AsnOutputStream();
        elem.encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, 0);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData3()));
    }

    @Test(groups = { "functional.xml.serialize", "circuitSwitchedCall" })
    public void testXMLSerializaion() throws Exception {
        ReceivingSideID partyToCharge = new ReceivingSideIDImpl(LegType.leg1);
        TimeInformation ti = new TimeInformationImpl(26);
        TimeDurationChargingResultImpl original = new TimeDurationChargingResultImpl(partyToCharge, ti, true, true,
                CAPExtensionsTest.createTestCAPExtensions(), null);

        // Writes the area to a file.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLObjectWriter writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "timeDurationChargingResult", TimeDurationChargingResultImpl.class);
        writer.close();

        byte[] rawData = baos.toByteArray();
        String serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
        XMLObjectReader reader = XMLObjectReader.newInstance(bais);
        TimeDurationChargingResultImpl copy = reader.read("timeDurationChargingResult", TimeDurationChargingResultImpl.class);

        assertEquals(copy.getPartyToCharge().getReceivingSideID(), original.getPartyToCharge().getReceivingSideID());
        assertEquals((int) copy.getTimeInformation().getTimeIfNoTariffSwitch(), (int) original.getTimeInformation()
                .getTimeIfNoTariffSwitch());
        assertEquals(copy.getLegActive(), original.getLegActive());
        assertEquals(copy.getCallLegReleasedAtTcpExpiry(), original.getCallLegReleasedAtTcpExpiry());
        assertTrue(CAPExtensionsTest.checkTestCAPExtensions(copy.getExtensions()));


        original = new TimeDurationChargingResultImpl(partyToCharge, ti, false, false, null, null);

        // Writes the area to a file.
        baos = new ByteArrayOutputStream();
        writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "timeDurationChargingResult", TimeDurationChargingResultImpl.class);
        writer.close();

        rawData = baos.toByteArray();
        serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        bais = new ByteArrayInputStream(rawData);
        reader = XMLObjectReader.newInstance(bais);
        copy = reader.read("timeDurationChargingResult", TimeDurationChargingResultImpl.class);

        assertEquals(copy.getPartyToCharge().getReceivingSideID(), original.getPartyToCharge().getReceivingSideID());
        assertEquals((int) copy.getTimeInformation().getTimeIfNoTariffSwitch(), (int) original.getTimeInformation()
                .getTimeIfNoTariffSwitch());
        assertEquals(copy.getLegActive(), original.getLegActive());
        assertEquals(copy.getCallLegReleasedAtTcpExpiry(), original.getCallLegReleasedAtTcpExpiry());
        assertNull(copy.getExtensions());
        assertNull(copy.getAChChargingAddress());


        AChChargingAddress aChChargingAddress = new AChChargingAddressImpl(13);
        original = new TimeDurationChargingResultImpl(partyToCharge, ti, false, false, null, aChChargingAddress);

        // Writes the area to a file.
        baos = new ByteArrayOutputStream();
        writer = XMLObjectWriter.newInstance(baos);
        // writer.setBinding(binding); // Optional.
        writer.setIndentation("\t"); // Optional (use tabulation for
                                     // indentation).
        writer.write(original, "timeDurationChargingResult", TimeDurationChargingResultImpl.class);
        writer.close();

        rawData = baos.toByteArray();
        serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        bais = new ByteArrayInputStream(rawData);
        reader = XMLObjectReader.newInstance(bais);
        copy = reader.read("timeDurationChargingResult", TimeDurationChargingResultImpl.class);

        assertEquals(copy.getPartyToCharge().getReceivingSideID(), original.getPartyToCharge().getReceivingSideID());
        assertEquals((int) copy.getTimeInformation().getTimeIfNoTariffSwitch(), (int) original.getTimeInformation()
                .getTimeIfNoTariffSwitch());
        assertEquals(copy.getLegActive(), original.getLegActive());
        assertEquals(copy.getCallLegReleasedAtTcpExpiry(), original.getCallLegReleasedAtTcpExpiry());
        assertNull(copy.getExtensions());
        assertEquals(copy.getAChChargingAddress().getSrfConnection(), original.getAChChargingAddress().getSrfConnection());
    }
}
