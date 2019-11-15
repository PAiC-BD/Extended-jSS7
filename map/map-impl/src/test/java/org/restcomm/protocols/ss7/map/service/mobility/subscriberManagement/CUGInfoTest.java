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
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.BearerServiceCodeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGFeature;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGInterlock;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGSubscription;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtBasicServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InterCUGRestrictions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InterCUGRestrictionsValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.IntraCUGOptions;
import org.restcomm.protocols.ss7.map.primitives.MAPExtensionContainerTest;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGFeatureImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGInterlockImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGSubscriptionImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtBasicServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtBearerServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.InterCUGRestrictionsImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class CUGInfoTest {

    public byte[] getData() {
        return new byte[] { 48, (byte) 129, (byte) 157, 48, 60, 48, 58, 2, 1, 1, 4, 4, 1, 2, 3, 4, 10, 1, 0, 48, 3, (byte) 130, 1, 38, (byte) 160, 39,
                (byte) 160, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, (byte) 161,
                3, 31, 32, 33, 48, 52, 48, 50, (byte) 130, 1, 38, 2, 1, 1, 4, 1, 0, 48, 39, (byte) 160, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5,
                6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, (byte) 161, 3, 31, 32, 33, (byte) 160, 39, (byte) 160, 32, 48, 10, 6, 3, 42, 3,
                4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, (byte) 161, 3, 31, 32, 33 };
    };

    private byte[] getGugData() {
        return new byte[] { 1, 2, 3, 4 };
    }

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        CUGInfoImpl prim = new CUGInfoImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.SEQUENCE);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        MAPExtensionContainer extensionContainer = prim.getExtensionContainer();
        assertNotNull(prim.getCUGSubscriptionList());
        assertTrue(prim.getCUGSubscriptionList().size() == 1);
        CUGSubscription cugSub = prim.getCUGSubscriptionList().get(0);
        assertNotNull(cugSub);
        assertEquals(cugSub.getCUGIndex(), 1);
        assertTrue(Arrays.equals(cugSub.getCugInterlock().getData(), getGugData()));
        assertEquals(cugSub.getIntraCugOptions(), IntraCUGOptions.noCUGRestrictions);
        ArrayList<ExtBasicServiceCode> basicServiceList = cugSub.getBasicServiceGroupList();
        assertEquals(basicServiceList.size(), 1);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(cugSub.getExtensionContainer()));

        assertNotNull(prim.getCUGFeatureList());
        assertTrue(prim.getCUGFeatureList().size() == 1);
        CUGFeature cugF = prim.getCUGFeatureList().get(0);
        assertNotNull(cugF);
        assertEquals(cugF.getBasicService().getExtBearerService().getBearerServiceCodeValue(),
                BearerServiceCodeValue.padAccessCA_9600bps);
        assertEquals((int) cugF.getPreferentialCugIndicator(), 1);
        assertEquals(cugF.getInterCugRestrictions().getInterCUGRestrictionsValue(), InterCUGRestrictionsValue.CUGOnlyFacilities);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(cugF.getExtensionContainer()));

        assertNotNull(extensionContainer);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainer));
    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {

        MAPExtensionContainer extensionContainer = MAPExtensionContainerTest.GetTestExtensionContainer();

        ExtBearerServiceCodeImpl b = new ExtBearerServiceCodeImpl(BearerServiceCodeValue.padAccessCA_9600bps);
        ExtBasicServiceCodeImpl basicService = new ExtBasicServiceCodeImpl(b);
        Integer preferentialCugIndicator = new Integer(1);
        InterCUGRestrictions interCugRestrictions = new InterCUGRestrictionsImpl(InterCUGRestrictionsValue.CUGOnlyFacilities);
        CUGFeatureImpl cugFeature = new CUGFeatureImpl(basicService, preferentialCugIndicator, interCugRestrictions,
                extensionContainer);
        ArrayList<CUGFeature> cugFeatureList = new ArrayList<CUGFeature>();
        cugFeatureList.add(cugFeature);

        ArrayList<CUGSubscription> cugSubscriptionList = new ArrayList<CUGSubscription>();
        int cugIndex = 1;
        CUGInterlock cugInterlock = new CUGInterlockImpl(getGugData());
        IntraCUGOptions intraCugOptions = IntraCUGOptions.noCUGRestrictions;
        ArrayList<ExtBasicServiceCode> basicServiceList = new ArrayList<ExtBasicServiceCode>();
        basicServiceList.add(basicService);
        CUGSubscriptionImpl cugSubscription = new CUGSubscriptionImpl(cugIndex, cugInterlock, intraCugOptions,
                basicServiceList, extensionContainer);
        cugSubscriptionList.add(cugSubscription);

        CUGInfoImpl prim = new CUGInfoImpl(cugSubscriptionList, cugFeatureList, extensionContainer);

        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);

        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));
    }
}
