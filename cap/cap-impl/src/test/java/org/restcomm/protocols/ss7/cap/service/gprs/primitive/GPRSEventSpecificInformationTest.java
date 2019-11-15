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
package org.restcomm.protocols.ss7.cap.service.gprs.primitive;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.EsiGprs.DetachSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.EsiGprs.DisconnectSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.EsiGprs.PDPContextEstablishmentAcknowledgementSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.EsiGprs.PDPContextEstablishmentSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.EsiGprs.PdpContextchangeOfPositionSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.api.EsiGprs.DetachSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.EsiGprs.DisconnectSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.EsiGprs.PDPContextEstablishmentAcknowledgementSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.EsiGprs.PDPContextEstablishmentSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.EsiGprs.PdpContextchangeOfPositionSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.primitives.TimeAndTimezone;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.AccessPointName;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.EndUserAddress;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.GPRSQoS;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.GPRSQoSExtension;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.InitiatingEntity;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPInitiationType;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPTypeNumberValue;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPTypeOrganizationValue;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.QualityOfService;
import org.restcomm.protocols.ss7.cap.primitives.TimeAndTimezoneImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.AccessPointNameImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.EndUserAddressImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.GPRSEventSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.GPRSQoSExtensionImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.GPRSQoSImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.PDPAddressImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.PDPTypeNumberImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.PDPTypeOrganizationImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.QualityOfServiceImpl;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.GSNAddress;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GPRSChargingID;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformationGPRS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdOrLAIImpl;
import org.restcomm.protocols.ss7.map.primitives.GSNAddressImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LAIFixedLengthImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GPRSChargingIDImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeodeticInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationInformationGPRSImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.Ext2QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.QoSSubscribedImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class GPRSEventSpecificInformationTest {

    public byte[] getData() {
        return new byte[] { -96, 57, -96, 7, -127, 5, 82, -16, 16, 17, 92, -127, 6, 11, 12, 13, 14, 15, 16, -126, 8, 31, 32,
                33, 34, 35, 36, 37, 38, -125, 4, -111, 86, 52, 18, -124, 3, 91, 92, 93, -122, 0, -121, 10, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, -120, 0, -119, 1, 13 };
    };

    public byte[] getData2() {
        return new byte[] { -95, -127, -119, -128, 3, 52, 20, 30, -127, 4, 41, 42, 43, 44, -94, 57, -96, 7, -127, 5, 82, -16,
                16, 17, 92, -127, 6, 11, 12, 13, 14, 15, 16, -126, 8, 31, 32, 33, 34, 35, 36, 37, 38, -125, 4, -111, 86, 52,
                18, -124, 3, 91, 92, 93, -122, 0, -121, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -120, 0, -119, 1, 13, -93, 11, -128,
                1, -15, -127, 1, 1, -126, 3, 4, 7, 7, -92, 35, -96, 5, -128, 3, 4, 7, 7, -95, 4, -127, 2, 1, 7, -94, 5, -128,
                3, 4, 7, 7, -93, 3, -128, 1, 52, -92, 3, -128, 1, 53, -91, 3, -128, 1, 54, -123, 8, 2, 17, 33, 3, 1, 112, -127,
                35, -122, 5, 1, 1, 1, 1, 1 };
    };

    public byte[] getData3() {
        return new byte[] { -94, 5, -128, 1, 2, -127, 0 };
    };

    public byte[] getData4() {
        return new byte[] { -93, 5, -128, 1, 2, -127, 0 };
    };

    public byte[] getData5() {
        return new byte[] { -92, -127, -127, -128, 3, 52, 20, 30, -95, 11, -128, 1, -15, -127, 1, 1, -126, 3, 4, 7, 7, -94, 35,
                -96, 5, -128, 3, 4, 7, 7, -95, 4, -127, 2, 1, 7, -94, 5, -128, 3, 4, 7, 7, -93, 3, -128, 1, 52, -92, 3, -128,
                1, 53, -91, 3, -128, 1, 54, -93, 57, -96, 7, -127, 5, 82, -16, 16, 17, 92, -127, 6, 11, 12, 13, 14, 15, 16,
                -126, 8, 31, 32, 33, 34, 35, 36, 37, 38, -125, 4, -111, 86, 52, 18, -124, 3, 91, 92, 93, -122, 0, -121, 10, 1,
                2, 3, 4, 5, 6, 7, 8, 9, 10, -120, 0, -119, 1, 13, -124, 8, 2, 17, 33, 3, 1, 112, -127, 35, -123, 1, 1, -122, 0 };
    };

    public byte[] getData6() {
        return new byte[] { -91, -127, -119, -128, 3, 52, 20, 30, -127, 4, 41, 42, 43, 44, -94, 57, -96, 7, -127, 5, 82, -16,
                16, 17, 92, -127, 6, 11, 12, 13, 14, 15, 16, -126, 8, 31, 32, 33, 34, 35, 36, 37, 38, -125, 4, -111, 86, 52,
                18, -124, 3, 91, 92, 93, -122, 0, -121, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -120, 0, -119, 1, 13, -93, 11, -128,
                1, -15, -127, 1, 1, -126, 3, 4, 7, 7, -92, 35, -96, 5, -128, 3, 4, 7, 7, -95, 4, -127, 2, 1, 7, -94, 5, -128,
                3, 4, 7, 7, -93, 3, -128, 1, 52, -92, 3, -128, 1, 53, -91, 3, -128, 1, 54, -123, 8, 2, 17, 33, 3, 1, 112, -127,
                35, -122, 5, 1, 1, 1, 1, 1 };
    };

    private byte[] getEncodedDataRAIdentity() {
        return new byte[] { 11, 12, 13, 14, 15, 16 };
    }

    private byte[] getGeographicalInformation() {
        return new byte[] { 31, 32, 33, 34, 35, 36, 37, 38 };
    }

    private byte[] getEncodedDataLSAIdentity() {
        return new byte[] { 91, 92, 93 };
    }

    private byte[] getGeodeticInformation() {
        return new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    }

    private byte[] getAccessPointNameData() {
        return new byte[] { 52, 20, 30 };
    }

    private byte[] getEncodedchargingId() {
        return new byte[] { 41, 42, 43, 44 };
    }

    public byte[] getPDPAddressData() {
        return new byte[] { 4, 7, 7 };
    };

    private byte[] getEncodedqos2Subscribed1() {
        return new byte[] { 52 };
    }

    private byte[] getEncodedqos2Subscribed2() {
        return new byte[] { 53 };
    }

    private byte[] getEncodedqos2Subscribed3() {
        return new byte[] { 54 };
    }

    public byte[] getQoSSubscribedData() {
        return new byte[] { 4, 7, 7 };
    };

    public byte[] getExtQoSSubscribedData() {
        return new byte[] { 1, 7 };
    };

    private byte[] getGSNAddressData() {
        return new byte[] { 1, 1, 1, 1, 1 };
    }

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {

        // Option 1
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        GPRSEventSpecificInformationImpl prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_locationInformationGPRS);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertEquals(prim.getLocationInformationGPRS().getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC(), 250);
        assertEquals(prim.getLocationInformationGPRS().getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC(), 1);
        assertEquals(prim.getLocationInformationGPRS().getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac(), 4444);

        // Option 2
        data = this.getData2();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_pdpContextchangeOfPositionSpecificInformation);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertTrue(Arrays.equals(prim.getPdpContextchangeOfPositionSpecificInformation().getAccessPointName().getData(),
                this.getAccessPointNameData()));
        assertTrue(Arrays.equals(prim.getPdpContextchangeOfPositionSpecificInformation().getChargingID().getData(),
                this.getEncodedchargingId()));
        assertEquals(prim.getPdpContextchangeOfPositionSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC(), 250);
        assertEquals(prim.getPdpContextchangeOfPositionSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC(), 1);
        assertEquals(prim.getPdpContextchangeOfPositionSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac(), 4444);

        // Option 3
        data = this.getData3();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_detachSpecificInformation);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertEquals(prim.getDetachSpecificInformation().getInitiatingEntity(), InitiatingEntity.hlr);
        assertTrue(prim.getDetachSpecificInformation().getRouteingAreaUpdate());

        // Option 4
        data = this.getData4();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_disconnectSpecificInformation);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertEquals(prim.getDisconnectSpecificInformation().getInitiatingEntity(), InitiatingEntity.hlr);
        assertTrue(prim.getDisconnectSpecificInformation().getRouteingAreaUpdate());

        // Option 5
        data = this.getData5();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_pdpContextEstablishmentSpecificInformation);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertTrue(Arrays.equals(prim.getPDPContextEstablishmentSpecificInformation().getAccessPointName().getData(),
                this.getAccessPointNameData()));
        assertEquals(prim.getPDPContextEstablishmentSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC(), 250);
        assertEquals(prim.getPDPContextEstablishmentSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC(), 1);
        assertEquals(prim.getPDPContextEstablishmentSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac(), 4444);

        // Option 6
        data = this.getData6();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new GPRSEventSpecificInformationImpl();
        prim.decodeAll(asn);

        assertEquals(tag, GPRSEventSpecificInformationImpl._ID_pdpContextEstablishmentAcknowledgementSpecificInformation);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertTrue(Arrays.equals(prim.getPDPContextEstablishmentAcknowledgementSpecificInformation().getAccessPointName()
                .getData(), this.getAccessPointNameData()));
        assertTrue(Arrays.equals(prim.getPDPContextEstablishmentAcknowledgementSpecificInformation().getChargingID().getData(),
                this.getEncodedchargingId()));
        assertEquals(prim.getPDPContextEstablishmentAcknowledgementSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC(), 250);
        assertEquals(prim.getPDPContextEstablishmentAcknowledgementSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC(), 1);
        assertEquals(prim.getPDPContextEstablishmentAcknowledgementSpecificInformation().getLocationInformationGPRS()
                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac(), 4444);

    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {

        // locationInformationGPRS - Option 1
        LAIFixedLengthImpl lai = new LAIFixedLengthImpl(250, 1, 4444);
        CellGlobalIdOrServiceAreaIdOrLAIImpl cgi = new CellGlobalIdOrServiceAreaIdOrLAIImpl(lai);
        RAIdentityImpl ra = new RAIdentityImpl(this.getEncodedDataRAIdentity());
        GeographicalInformationImpl ggi = new GeographicalInformationImpl(this.getGeographicalInformation());
        ISDNAddressStringImpl sgsn = new ISDNAddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "654321");
        LSAIdentityImpl lsa = new LSAIdentityImpl(this.getEncodedDataLSAIdentity());
        GeodeticInformationImpl gdi = new GeodeticInformationImpl(this.getGeodeticInformation());
        LocationInformationGPRS locationInformationGPRS = new LocationInformationGPRSImpl(cgi, ra, ggi, sgsn, lsa, null, true,
                gdi, true, 13);

        // pdpContextchangeOfPositionSpecificInformation - Option 2
        AccessPointName accessPointName = new AccessPointNameImpl(this.getAccessPointNameData());
        GPRSChargingID chargingID = new GPRSChargingIDImpl(getEncodedchargingId());
        PDPAddressImpl pdpAddress = new PDPAddressImpl(getPDPAddressData());
        PDPTypeNumberImpl pdpTypeNumber = new PDPTypeNumberImpl(PDPTypeNumberValue.PPP);
        PDPTypeOrganizationImpl pdpTypeOrganization = new PDPTypeOrganizationImpl(PDPTypeOrganizationValue.ETSI);
        EndUserAddress endUserAddress = new EndUserAddressImpl(pdpTypeOrganization, pdpTypeNumber, pdpAddress);
        QoSSubscribed qosSubscribed = new QoSSubscribedImpl(this.getQoSSubscribedData());
        GPRSQoS requestedQoS = new GPRSQoSImpl(qosSubscribed);
        ExtQoSSubscribed extQoSSubscribed = new ExtQoSSubscribedImpl(this.getExtQoSSubscribedData());
        GPRSQoS subscribedQoS = new GPRSQoSImpl(extQoSSubscribed);
        GPRSQoS negotiatedQoS = new GPRSQoSImpl(qosSubscribed);
        Ext2QoSSubscribedImpl qos2Subscribed1 = new Ext2QoSSubscribedImpl(this.getEncodedqos2Subscribed1());
        GPRSQoSExtension requestedQoSExtension = new GPRSQoSExtensionImpl(qos2Subscribed1);
        Ext2QoSSubscribedImpl qos2Subscribed2 = new Ext2QoSSubscribedImpl(this.getEncodedqos2Subscribed2());
        GPRSQoSExtension subscribedQoSExtension = new GPRSQoSExtensionImpl(qos2Subscribed2);
        Ext2QoSSubscribedImpl qos2Subscribed3 = new Ext2QoSSubscribedImpl(this.getEncodedqos2Subscribed3());
        GPRSQoSExtension negotiatedQoSExtension = new GPRSQoSExtensionImpl(qos2Subscribed3);
        QualityOfService qualityOfService = new QualityOfServiceImpl(requestedQoS, subscribedQoS, negotiatedQoS,
                requestedQoSExtension, subscribedQoSExtension, negotiatedQoSExtension);
        TimeAndTimezone timeAndTimezone = new TimeAndTimezoneImpl(2011, 12, 30, 10, 7, 18, 32);
        GSNAddress gsnAddress = new GSNAddressImpl(getGSNAddressData());
        PdpContextchangeOfPositionSpecificInformation pdpContextchangeOfPositionSpecificInformation = new PdpContextchangeOfPositionSpecificInformationImpl(
                accessPointName, chargingID, locationInformationGPRS, endUserAddress, qualityOfService, timeAndTimezone,
                gsnAddress);

        // detachSpecificInformation - Option 3
        DetachSpecificInformation detachSpecificInformation = new DetachSpecificInformationImpl(InitiatingEntity.hlr, true);

        // disconnectSpecificInformation - Option 4
        DisconnectSpecificInformation disconnectSpecificInformation = new DisconnectSpecificInformationImpl(
                InitiatingEntity.hlr, true);

        // pdpContextEstablishmentSpecificInformation - Option 5
        PDPContextEstablishmentSpecificInformation pdpContextEstablishmentSpecificInformation = new PDPContextEstablishmentSpecificInformationImpl(
                accessPointName, endUserAddress, qualityOfService, locationInformationGPRS, timeAndTimezone,
                PDPInitiationType.networkInitiated, true);

        // pdpContextEstablishmentAcknowledgementSpecificInformation - Option 6
        PDPContextEstablishmentAcknowledgementSpecificInformation pdpContextEstablishmentAcknowledgementSpecificInformation = new PDPContextEstablishmentAcknowledgementSpecificInformationImpl(
                accessPointName, chargingID, locationInformationGPRS, endUserAddress, qualityOfService, timeAndTimezone,
                gsnAddress);

        // option 1
        GPRSEventSpecificInformationImpl prim = new GPRSEventSpecificInformationImpl(locationInformationGPRS);
        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));

        // option 2
        prim = new GPRSEventSpecificInformationImpl(pdpContextchangeOfPositionSpecificInformation);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData2()));

        // option 3
        prim = new GPRSEventSpecificInformationImpl(detachSpecificInformation);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData3()));

        // option 4
        prim = new GPRSEventSpecificInformationImpl(disconnectSpecificInformation);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData4()));

        // option 5
        prim = new GPRSEventSpecificInformationImpl(pdpContextEstablishmentSpecificInformation);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData5()));

        // option 6
        prim = new GPRSEventSpecificInformationImpl(pdpContextEstablishmentAcknowledgementSpecificInformation);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData6()));

    }

}
