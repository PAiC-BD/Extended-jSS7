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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.cap.isup.DigitsImpl;
import org.restcomm.protocols.ss7.cap.primitives.CAPExtensionsTest;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.AssistRequestInstructionsRequestImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.IPSSPCapabilitiesImpl;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.GenericNumberImpl;
import org.testng.annotations.Test;

public class AssistRequestInstructionsRequestTest {

    public byte[] getData1() {
        return new byte[] { 48, 33, (byte) 128, 8, 0, (byte) 128, 20, 17, 33, 34, 51, 3, (byte) 130, 1, 111, (byte) 163, 18,
                48, 5, 2, 1, 2, (byte) 129, 0, 48, 9, 2, 1, 3, 10, 1, 1, (byte) 129, 1, (byte) 255 };
    }

    public byte[] getIPSSPCapabilitiesInt() {
        return new byte[] { 111 };
    }

    public byte[] getGenericNumberInt() {
        return new byte[] { 0, -128, 20, 17, 33, 34, 51, 3 };
    }

    @Test(groups = { "functional.decode", "circuitSwitchedCall" })
    public void testDecode() throws Exception {

        byte[] data = this.getData1();
        AsnInputStream ais = new AsnInputStream(data);
        AssistRequestInstructionsRequestImpl elem = new AssistRequestInstructionsRequestImpl();
        int tag = ais.readTag();
        elem.decodeAll(ais);

        assertEquals(elem.getCorrelationID().getGenericNumber().getNatureOfAddressIndicator(), 0);
        assertTrue(elem.getCorrelationID().getGenericNumber().getAddress().equals("111222333"));
        assertEquals(elem.getCorrelationID().getGenericNumber().getNumberQualifierIndicator(), 0);
        assertEquals(elem.getCorrelationID().getGenericNumber().getNumberingPlanIndicator(), 1);
        assertEquals(elem.getCorrelationID().getGenericNumber().getAddressRepresentationRestrictedIndicator(), 1);
        assertEquals(elem.getCorrelationID().getGenericNumber().getScreeningIndicator(), 0);
        assertTrue(Arrays.equals(elem.getIPSSPCapabilities().getData(), getIPSSPCapabilitiesInt()));
        assertTrue(CAPExtensionsTest.checkTestCAPExtensions(elem.getExtensions()));
    }

    @Test(groups = { "functional.encode", "circuitSwitchedCall" })
    public void testEncode() throws Exception {

        GenericNumberImpl genericNumber = new GenericNumberImpl(0, "111222333", 0, 1, 1, false, 0);
        // GenericNumberImpl genericNumber = new GenericNumberImpl(getGenericNumberInt());
        // int natureOfAddresIndicator, String address, int numberQualifierIndicator, int numberingPlanIndicator, int
        // addressRepresentationREstrictedIndicator,
        // boolean numberIncomplete, int screeningIndicator
        DigitsImpl correlationID = new DigitsImpl(genericNumber);
        IPSSPCapabilitiesImpl ipSSPCapabilities = new IPSSPCapabilitiesImpl(getIPSSPCapabilitiesInt());

        AssistRequestInstructionsRequestImpl elem = new AssistRequestInstructionsRequestImpl(correlationID, ipSSPCapabilities,
                CAPExtensionsTest.createTestCAPExtensions());
        AsnOutputStream aos = new AsnOutputStream();
        elem.encodeAll(aos);
        assertTrue(Arrays.equals(aos.toByteArray(), this.getData1()));

        // Digits correlationID, IPSSPCapabilities ipSSPCapabilities, CAPExtensions extensions
    }
}
