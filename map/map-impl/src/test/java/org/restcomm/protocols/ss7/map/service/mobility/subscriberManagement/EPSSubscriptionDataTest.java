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
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LIPAPermission;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SIPTOPermission;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AMBR;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APN;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNConfiguration;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNConfigurationProfile;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNOIReplacement;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AllocationRetentionPriority;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ChargingCharacteristics;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.EPSQoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.FQDN;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNGWAllocationType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNGWIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNTypeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDPAddress;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSClassIdentifier;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SpecificAPNInfo;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.MAPExtensionContainerTest;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AMBRImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNConfigurationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNConfigurationProfileImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNOIReplacementImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AllocationRetentionPriorityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ChargingCharacteristicsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EPSQoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EPSSubscriptionDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.FQDNImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDNGWIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDNTypeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDPAddressImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SpecificAPNInfoImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class EPSSubscriptionDataTest {

    public byte[] getData() {
        return new byte[] { 48, -126, 2, 73, -128, 9, 48, 12, 17, 17, 119, 22, 62, 34, 12, -126, 1, 4, -93, 47, -128, 1, 2,
                -127, 1, 4, -94, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3,
                42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, -92, -126, 1, -45, 2, 1, 2, 5, 0, -95, -126, 1, -95, 48,
                -126, 1, -99, -128, 1, 1, -127, 1, 1, -126, 3, 5, 6, 7, -125, 2, 6, 7, -92, 96, -128, 1, 1, -95, 50, -128, 1,
                1, -127, 1, -1, -126, 1, -1, -93, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3,
                6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, -94, 39, -96, 32, 48, 10, 6, 3, 42, 3,
                4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32,
                33, -91, 63, -128, 3, 5, 6, 7, -127, 3, 5, 6, 7, -126, 10, 4, 1, 6, 8, 3, 2, 5, 6, 1, 7, -93, 39, -96, 32, 48,
                10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26,
                -95, 3, 31, 32, 33, -122, 1, 1, -121, 0, -120, 2, 6, 5, -87, 47, -128, 1, 2, -127, 1, 4, -94, 39, -96, 32, 48,
                10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26,
                -95, 3, 31, 32, 33, -86, 112, 48, 110, -128, 2, 6, 7, -95, 63, -128, 3, 5, 6, 7, -127, 3, 5, 6, 7, -126, 10, 4,
                1, 6, 8, 3, 2, 5, 6, 1, 7, -93, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6,
                48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, -94, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4,
                11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33,
                -85, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5,
                21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, -116, 3, 5, 6, 7, -115, 9, 48, 12, 17, 17, 119, 22, 62, 34, 12,
                -114, 1, 0, -113, 1, 2, -94, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6,
                48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, -122, 4, -111, 34, 34, -8, -91, 39, -96,
                32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24,
                25, 26, -95, 3, 31, 32, 33, -121, 0, -120, 0 };
    };

    public byte[] getAPNOIReplacementData() {
        return new byte[] { 48, 12, 17, 17, 119, 22, 62, 34, 12 };
    };

    public byte[] getPDPAddressData() {
        return new byte[] { 5, 6, 7 };
    };

    public byte[] getAPNData() {
        return new byte[] { 6, 7 };
    };

    public byte[] getFQDNData() {
        return new byte[] { 4, 1, 6, 8, 3, 2, 5, 6, 1, 7 };
    };

    public byte[] getChargingCharacteristicsData() {
        return new byte[] { 6, 5 };
    };

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();

        EPSSubscriptionDataImpl prim = new EPSSubscriptionDataImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.SEQUENCE);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        AMBR ambrPrim = prim.getAmbr();
        MAPExtensionContainer extensionContainerambrambrPrim = ambrPrim.getExtensionContainer();
        assertEquals(ambrPrim.getMaxRequestedBandwidthDL(), 4);
        assertEquals(ambrPrim.getMaxRequestedBandwidthUL(), 2);
        assertNotNull(extensionContainerambrambrPrim);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainerambrambrPrim));

        assertTrue(Arrays.equals(prim.getApnOiReplacement().getData(), this.getAPNOIReplacementData()));
        MAPExtensionContainer primMAPExtensionContainer = prim.getExtensionContainer();
        assertNotNull(primMAPExtensionContainer);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(primMAPExtensionContainer));

        assertTrue(prim.getMpsCSPriority());
        assertTrue(prim.getMpsEPSPriority());

        assertEquals(prim.getRfspId().intValue(), 4);

        ISDNAddressString stnSr = prim.getStnSr();
        assertTrue(stnSr.getAddress().equals("22228"));
        assertEquals(stnSr.getAddressNature(), AddressNature.international_number);
        assertEquals(stnSr.getNumberingPlan(), NumberingPlan.ISDN);

        APNConfigurationProfile apnConfigurationProfile = prim.getAPNConfigurationProfile();

        assertEquals(apnConfigurationProfile.getDefaultContext(), 2);
        assertTrue(apnConfigurationProfile.getCompleteDataListIncluded());
        MAPExtensionContainer apnConfigurationProfileExtensionContainer = apnConfigurationProfile.getExtensionContainer();
        assertNotNull(apnConfigurationProfileExtensionContainer);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(apnConfigurationProfileExtensionContainer));

        ArrayList<APNConfiguration> ePSDataList = apnConfigurationProfile.getEPSDataList();
        assertNotNull(ePSDataList);
        assertEquals(ePSDataList.size(), 1);

        APNConfiguration apnConfiguration = ePSDataList.get(0);
        assertEquals(apnConfiguration.getContextId(), 1);
        assertEquals(apnConfiguration.getPDNType().getPDNTypeValue(), PDNTypeValue.IPv4);
        PDPAddress servedPartyIPIPv4Address = apnConfiguration.getServedPartyIPIPv4Address();
        assertNotNull(servedPartyIPIPv4Address);
        assertTrue(Arrays.equals(this.getPDPAddressData(), servedPartyIPIPv4Address.getData()));
        assertTrue(Arrays.equals(apnConfiguration.getApn().getData(), this.getAPNData()));

        EPSQoSSubscribed ePSQoSSubscribed = apnConfiguration.getEPSQoSSubscribed();
        AllocationRetentionPriority allocationRetentionPriority = ePSQoSSubscribed.getAllocationRetentionPriority();
        MAPExtensionContainer extensionContainerePSQoSSubscribed = ePSQoSSubscribed.getExtensionContainer();
        assertEquals(allocationRetentionPriority.getPriorityLevel(), 1);
        assertTrue(allocationRetentionPriority.getPreEmptionCapability());
        assertTrue(allocationRetentionPriority.getPreEmptionVulnerability());
        assertNotNull(allocationRetentionPriority.getExtensionContainer());
        ;
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(allocationRetentionPriority.getExtensionContainer()));
        assertNotNull(extensionContainerePSQoSSubscribed);
        assertEquals(ePSQoSSubscribed.getQoSClassIdentifier(), QoSClassIdentifier.QCI_1);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainerePSQoSSubscribed));

        PDNGWIdentity pdnGWIdentity = apnConfiguration.getPdnGwIdentity();
        PDPAddress pdnGwIpv4Address = pdnGWIdentity.getPdnGwIpv4Address();
        assertNotNull(pdnGwIpv4Address);
        assertTrue(Arrays.equals(this.getPDPAddressData(), pdnGwIpv4Address.getData()));
        PDPAddress pdnGwIpv6Address = pdnGWIdentity.getPdnGwIpv6Address();
        assertNotNull(pdnGwIpv6Address);
        assertTrue(Arrays.equals(this.getPDPAddressData(), pdnGwIpv6Address.getData()));
        FQDN pdnGwName = pdnGWIdentity.getPdnGwName();
        assertNotNull(pdnGwName);
        assertTrue(Arrays.equals(this.getFQDNData(), pdnGwName.getData()));
        assertNotNull(pdnGWIdentity.getExtensionContainer());
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(pdnGWIdentity.getExtensionContainer()));

        assertEquals(apnConfiguration.getPdnGwAllocationType(), PDNGWAllocationType._dynamic);
        assertTrue(apnConfiguration.getVplmnAddressAllowed());
        assertTrue(Arrays
                .equals(this.getChargingCharacteristicsData(), apnConfiguration.getChargingCharacteristics().getData()));

        AMBR ambr = apnConfiguration.getAmbr();
        MAPExtensionContainer extensionContainerambr = ambr.getExtensionContainer();
        assertEquals(ambr.getMaxRequestedBandwidthDL(), 4);
        assertEquals(ambr.getMaxRequestedBandwidthUL(), 2);
        assertNotNull(extensionContainerambr);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainerambr));

        ArrayList<SpecificAPNInfo> specificAPNInfoList = apnConfiguration.getSpecificAPNInfoList();
        assertNotNull(specificAPNInfoList);
        assertEquals(specificAPNInfoList.size(), 1);
        SpecificAPNInfo specificAPNInfo = specificAPNInfoList.get(0);

        PDNGWIdentity pdnGWIdentitySpecificAPNInfo = specificAPNInfo.getPdnGwIdentity();
        PDPAddress pdnGwIpv4AddressSpecificAPNInfo = pdnGWIdentitySpecificAPNInfo.getPdnGwIpv4Address();
        assertNotNull(pdnGwIpv4AddressSpecificAPNInfo);
        assertTrue(Arrays.equals(this.getPDPAddressData(), pdnGwIpv4AddressSpecificAPNInfo.getData()));
        PDPAddress pdnGwIpv6AddressSpecificAPNInfo = pdnGWIdentitySpecificAPNInfo.getPdnGwIpv6Address();
        assertNotNull(pdnGwIpv6AddressSpecificAPNInfo);
        assertTrue(Arrays.equals(this.getPDPAddressData(), pdnGwIpv6AddressSpecificAPNInfo.getData()));
        FQDN pdnGwNameSpecificAPNInfo = pdnGWIdentitySpecificAPNInfo.getPdnGwName();
        assertNotNull(pdnGwNameSpecificAPNInfo);
        assertTrue(Arrays.equals(this.getFQDNData(), pdnGwNameSpecificAPNInfo.getData()));
        assertNotNull(pdnGWIdentitySpecificAPNInfo.getExtensionContainer());
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(pdnGWIdentitySpecificAPNInfo.getExtensionContainer()));
        MAPExtensionContainer extensionContainerspecificAPNInfo = specificAPNInfo.getExtensionContainer();
        assertNotNull(extensionContainerspecificAPNInfo);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainerspecificAPNInfo));

        assertTrue(Arrays.equals(specificAPNInfo.getAPN().getData(), this.getAPNData()));

        PDPAddress servedPartyIPIPv6Address = apnConfiguration.getServedPartyIPIPv6Address();
        assertNotNull(servedPartyIPIPv6Address);
        assertTrue(Arrays.equals(this.getPDPAddressData(), servedPartyIPIPv6Address.getData()));
        assertTrue(Arrays.equals(this.getAPNOIReplacementData(), apnConfiguration.getApnOiReplacement().getData()));
        assertEquals(apnConfiguration.getSiptoPermission(), SIPTOPermission.siptoAllowed);
        assertEquals(apnConfiguration.getLipaPermission(), LIPAPermission.lipaConditional);
        MAPExtensionContainer extensionContainer = apnConfiguration.getExtensionContainer();
        assertNotNull(extensionContainer);
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(extensionContainer));
    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {
        MAPExtensionContainer extensionContainer = MAPExtensionContainerTest.GetTestExtensionContainer();
        APNOIReplacement apnOiReplacement = new APNOIReplacementImpl(this.getAPNOIReplacementData());
        Integer rfspId = new Integer(4);
        AMBR ambr = new AMBRImpl(2, 4, extensionContainer);

        int defaultContext = 2;
        boolean completeDataListIncluded = true;
        ArrayList<APNConfiguration> ePSDataList = new ArrayList<APNConfiguration>();

        int contextId = 1;
        PDNType pDNType = new PDNTypeImpl(PDNTypeValue.IPv4);
        PDPAddress servedPartyIPIPv4Address = new PDPAddressImpl(this.getPDPAddressData());
        APN apn = new APNImpl(this.getAPNData());

        QoSClassIdentifier qoSClassIdentifier = QoSClassIdentifier.QCI_1;
        AllocationRetentionPriority allocationRetentionPriority = new AllocationRetentionPriorityImpl(1, Boolean.TRUE,
                Boolean.TRUE, extensionContainer);
        EPSQoSSubscribed ePSQoSSubscribed = new EPSQoSSubscribedImpl(qoSClassIdentifier, allocationRetentionPriority,
                extensionContainer);

        PDPAddress pdnGwIpv4Address = new PDPAddressImpl(this.getPDPAddressData());
        PDPAddress pdnGwIpv6Address = new PDPAddressImpl(this.getPDPAddressData());
        FQDN pdnGwName = new FQDNImpl(this.getFQDNData());
        PDNGWIdentity pdnGwIdentity = new PDNGWIdentityImpl(pdnGwIpv4Address, pdnGwIpv6Address, pdnGwName, extensionContainer);

        PDNGWAllocationType pdnGwAllocationType = PDNGWAllocationType._dynamic;
        boolean vplmnAddressAllowed = true;
        ChargingCharacteristics chargingCharacteristics = new ChargingCharacteristicsImpl(this.getChargingCharacteristicsData());

        SpecificAPNInfo specificAPNInfo = new SpecificAPNInfoImpl(apn, pdnGwIdentity, extensionContainer);
        ArrayList<SpecificAPNInfo> specificAPNInfoList = new ArrayList<SpecificAPNInfo>();
        specificAPNInfoList.add(specificAPNInfo);

        PDPAddress servedPartyIPIPv6Address = new PDPAddressImpl(this.getPDPAddressData());
        SIPTOPermission siptoPermission = SIPTOPermission.siptoAllowed;
        LIPAPermission lipaPermission = LIPAPermission.lipaConditional;

        APNConfiguration APNConfiguration = new APNConfigurationImpl(contextId, pDNType, servedPartyIPIPv4Address, apn,
                ePSQoSSubscribed, pdnGwIdentity, pdnGwAllocationType, vplmnAddressAllowed, chargingCharacteristics, ambr,
                specificAPNInfoList, extensionContainer, servedPartyIPIPv6Address, apnOiReplacement, siptoPermission,
                lipaPermission);

        ePSDataList.add(APNConfiguration);

        APNConfigurationProfile apnConfigurationProfile = new APNConfigurationProfileImpl(defaultContext,
                completeDataListIncluded, ePSDataList, extensionContainer);

        ISDNAddressString stnSr = new ISDNAddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "22228");
        boolean mpsCSPriority = true;
        boolean mpsEPSPriority = true;

        EPSSubscriptionDataImpl prim = new EPSSubscriptionDataImpl(apnOiReplacement, rfspId, ambr, apnConfigurationProfile,
                stnSr, extensionContainer, mpsCSPriority, mpsEPSPriority);
        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);

        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));
    }

}
