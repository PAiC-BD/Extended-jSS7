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

package org.restcomm.protocols.ss7.map.service.callhandling;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DefaultCallHandling;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OBcsmCamelTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OBcsmTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TBcsmCamelTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TBcsmTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TCSI;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.GmscCamelSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OBcsmCamelTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TBcsmCamelTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TCSIImpl;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class GmscCamelSubscriptionInfoTest {

    private byte[] getEncodedData() {
        return new byte[] { -96, 50, -96, 23, 48, 18, 48, 16, 10, 1, 12, 2, 1, 3, -128, 5, -111, 17, 34, 51, -13, -127, 1, 1,
                -128, 1, 2, -95, 23, 48, 18, 48, 16, 10, 1, 2, 2, 1, 3, -128, 5, -111, 17, 34, 51, -13, -127, 1, 1, -128, 1, 2 };
    }

    @Test(groups = { "functional.decode", "service.mobility.subscriberManagement" })
    public void testDecode() throws Exception {

        byte[] rawData = getEncodedData();
        AsnInputStream asn = new AsnInputStream(rawData);

        int tag = asn.readTag();
        GmscCamelSubscriptionInfoImpl ind = new GmscCamelSubscriptionInfoImpl();
        assertEquals(tag, 0);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        ind.decodeAll(asn);

        TCSI tcsi = ind.getTCsi();
        ArrayList<TBcsmCamelTDPData> lst = tcsi.getTBcsmCamelTDPDataList();
        assertEquals(lst.size(), 1);
        TBcsmCamelTDPData cd = lst.get(0);
        assertEquals(cd.getTBcsmTriggerDetectionPoint(), TBcsmTriggerDetectionPoint.termAttemptAuthorized);
        assertEquals(cd.getServiceKey(), 3);
        assertEquals(cd.getGsmSCFAddress().getAddressNature(), AddressNature.international_number);
        assertEquals(cd.getGsmSCFAddress().getNumberingPlan(), NumberingPlan.ISDN);
        assertTrue(cd.getGsmSCFAddress().getAddress().equals("1122333"));
        assertEquals(cd.getDefaultCallHandling(), DefaultCallHandling.releaseCall);
        assertNull(cd.getExtensionContainer());

        assertNull(tcsi.getExtensionContainer());
        assertEquals((int) tcsi.getCamelCapabilityHandling(), 2);
        assertFalse(tcsi.getNotificationToCSE());
        assertFalse(tcsi.getCsiActive());

        OCSI ocsi = ind.getOCsi();
        ArrayList<OBcsmCamelTDPData> lst2 = ocsi.getOBcsmCamelTDPDataList();
        assertEquals(lst2.size(), 1);
        OBcsmCamelTDPData cd2 = lst2.get(0);
        assertEquals(cd2.getOBcsmTriggerDetectionPoint(), OBcsmTriggerDetectionPoint.collectedInfo);
        assertEquals(cd2.getServiceKey(), 3);
        assertEquals(cd2.getGsmSCFAddress().getAddressNature(), AddressNature.international_number);
        assertEquals(cd2.getGsmSCFAddress().getNumberingPlan(), NumberingPlan.ISDN);
        assertTrue(cd2.getGsmSCFAddress().getAddress().equals("1122333"));
        assertEquals(cd2.getDefaultCallHandling(), DefaultCallHandling.releaseCall);
        assertNull(cd2.getExtensionContainer());

        assertNull(ocsi.getExtensionContainer());
        assertEquals((int) ocsi.getCamelCapabilityHandling(), 2);
        assertFalse(ocsi.getNotificationToCSE());
        assertFalse(ocsi.getCsiActive());

        // TODO: implement tests for missing and not yet implementing parameters
    }

    @Test(groups = { "functional.encode", "service.mobility.subscriberManagement" })
    public void testEncode() throws Exception {

        ISDNAddressStringImpl gsmSCFAddress = new ISDNAddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN,
                "1122333");
        TBcsmCamelTDPDataImpl cind = new TBcsmCamelTDPDataImpl(TBcsmTriggerDetectionPoint.termAttemptAuthorized, 3,
                gsmSCFAddress, DefaultCallHandling.releaseCall, null);
        ArrayList<TBcsmCamelTDPData> lst = new ArrayList<TBcsmCamelTDPData>();
        lst.add(cind);
        TCSIImpl ctsi = new TCSIImpl(lst, null, 2, false, false);

        OBcsmCamelTDPDataImpl oind = new OBcsmCamelTDPDataImpl(OBcsmTriggerDetectionPoint.collectedInfo, 3, gsmSCFAddress,
                DefaultCallHandling.releaseCall, null);
        ArrayList<OBcsmCamelTDPData> lst2 = new ArrayList<OBcsmCamelTDPData>();
        lst2.add(oind);
        OCSIImpl otsi = new OCSIImpl(lst2, null, 2, false, false);

        GmscCamelSubscriptionInfoImpl ind = new GmscCamelSubscriptionInfoImpl(ctsi, otsi, null, null, null, null);

        AsnOutputStream asnOS = new AsnOutputStream();
        ind.encodeAll(asnOS, Tag.CLASS_CONTEXT_SPECIFIC, 0);

        byte[] encodedData = asnOS.toByteArray();
        byte[] rawData = getEncodedData();
        assertTrue(Arrays.equals(rawData, encodedData));

        // TODO: implement tests for missing and not yet implementing parameters

    }

}
