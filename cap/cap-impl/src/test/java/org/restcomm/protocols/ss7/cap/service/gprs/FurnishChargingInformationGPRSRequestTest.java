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
package org.restcomm.protocols.ss7.cap.service.gprs;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.primitives.AppendFreeFormatData;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.FreeFormatDataGprs;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPID;
import org.restcomm.protocols.ss7.cap.service.gprs.FurnishChargingInformationGPRSRequestImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.CAMELFCIGPRSBillingChargingCharacteristicsImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.FCIBCCCAMELsequence1GprsImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.FreeFormatDataGprsImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.PDPIDImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class FurnishChargingInformationGPRSRequestTest {

    public byte[] getData() {
        return new byte[] { 4, 20, 48, 18, -96, 16, -128, 8, 48, 6, -128, 1, 5, -127, 1, 2, -127, 1, 2, -126, 1, 1 };
    };

    public byte[] getFreeFormatData() {
        return new byte[] { 48, 6, -128, 1, 5, -127, 1, 2 };
    };

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        FurnishChargingInformationGPRSRequestImpl prim = new FurnishChargingInformationGPRSRequestImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertEquals(prim.getFCIGPRSBillingChargingCharacteristics().getFCIBCCCAMELsequence1().getFreeFormatData().getData(),
                this.getFreeFormatData());
        assertEquals(prim.getFCIGPRSBillingChargingCharacteristics().getFCIBCCCAMELsequence1().getPDPID().getId(), 2);
        assertEquals(prim.getFCIGPRSBillingChargingCharacteristics().getFCIBCCCAMELsequence1().getAppendFreeFormatData(),
                AppendFreeFormatData.append);
    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {

        FreeFormatDataGprs freeFormatData = new FreeFormatDataGprsImpl(this.getFreeFormatData());
        PDPID pdpID = new PDPIDImpl(2);
        FCIBCCCAMELsequence1GprsImpl fcIBCCCAMELsequence1 = new FCIBCCCAMELsequence1GprsImpl(freeFormatData, pdpID,
                AppendFreeFormatData.append);

        CAMELFCIGPRSBillingChargingCharacteristicsImpl fciGPRSBillingChargingCharacteristics = new CAMELFCIGPRSBillingChargingCharacteristicsImpl(
                fcIBCCCAMELsequence1);

        FurnishChargingInformationGPRSRequestImpl prim = new FurnishChargingInformationGPRSRequestImpl(
                fciGPRSBillingChargingCharacteristics);
        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));
    }

}
