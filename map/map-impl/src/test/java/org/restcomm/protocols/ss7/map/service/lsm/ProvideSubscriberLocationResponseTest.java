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

package org.restcomm.protocols.ss7.map.service.lsm;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.MAPParameterFactoryImpl;
import org.restcomm.protocols.ss7.map.api.MAPParameterFactory;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.lsm.AccuracyFulfilmentIndicator;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdOrLAIImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LAIFixedLengthImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AddGeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ExtGeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.GeranGANSSpositioningDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.PositioningDataInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ProvideSubscriberLocationResponseImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ServingNodeAddressImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranGANSSpositioningDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranPositioningDataInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.VelocityEstimateImpl;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 *
 *
 * @author sergey vetyutnev
 *
 */
public class ProvideSubscriberLocationResponseTest {

    MAPParameterFactory MAPParameterFactory = new MAPParameterFactoryImpl();

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeTest
    public void setUp() {
    }

    @AfterTest
    public void tearDown() {
    }

    public byte[] getEncodedData() {
        return new byte[] { 48, 6, 4, 1, 99, -128, 1, 15 };
    }

    public byte[] getEncodedDataFull() {
        return new byte[] { 48, 59, 4, 1, 99, -128, 1, 15, -126, 1, 19, -125, 0, -124, 2, 11, 12, -123, 3, 15, 16, 17, -90, 7,
                -127, 5, 33, -15, 16, 8, -82, -121, 0, -120, 1, 0, -119, 4, 21, 22, 23, 24, -118, 0, -117, 2, 25, 26, -116, 1,
                29, -83, 8, -128, 6, -111, 68, 100, 102, -120, -8 };
    }

    public byte[] getExtGeographicalInformation() {
        return new byte[] { 99 };
    }

    public byte[] getPositioningDataInformation() {
        return new byte[] { 11, 12 };
    }

    public byte[] getUtranPositioningDataInfo() {
        return new byte[] { 15, 16, 17 };
    }

    public byte[] getAddGeographicalInformation() {
        return new byte[] { 19 };
    }

    public byte[] getVelocityEstimate() {
        return new byte[] { 21, 22, 23, 24 };
    }

    public byte[] getGeranGANSSpositioningData() {
        return new byte[] { 25, 26 };
    }

    public byte[] getUtranGANSSpositioningData() {
        return new byte[] { 29 };
    }

    @Test(groups = { "functional.decode", "service.lsm" })
    public void testDecodeProvideSubscriberLocationRequestIndication() throws Exception {
        byte[] rawData = getEncodedData();

        AsnInputStream asn = new AsnInputStream(rawData);

        int tag = asn.readTag();
        assertEquals(tag, Tag.SEQUENCE);

        ProvideSubscriberLocationResponseImpl impl = new ProvideSubscriberLocationResponseImpl();
        impl.decodeAll(asn);

        assertTrue(Arrays.equals(impl.getLocationEstimate().getData(), getExtGeographicalInformation()));
        assertEquals((int) impl.getAgeOfLocationEstimate(), 15);

        assertNull(impl.getExtensionContainer());
        assertNull(impl.getAdditionalLocationEstimate());
        assertFalse(impl.getDeferredMTLRResponseIndicator());
        assertNull(impl.getGeranPositioningData());
        assertNull(impl.getUtranPositioningData());
        assertNull(impl.getCellIdOrSai());
        assertFalse(impl.getSaiPresent());
        assertNull(impl.getAccuracyFulfilmentIndicator());
        assertNull(impl.getVelocityEstimate());
        assertFalse(impl.getMoLrShortCircuitIndicator());
        assertNull(impl.getGeranGANSSpositioningData());
        assertNull(impl.getUtranGANSSpositioningData());
        assertNull(impl.getTargetServingNodeForHandover());

        rawData = getEncodedDataFull();

        asn = new AsnInputStream(rawData);

        tag = asn.readTag();
        assertEquals(tag, Tag.SEQUENCE);

        impl = new ProvideSubscriberLocationResponseImpl();
        impl.decodeAll(asn);

        assertTrue(Arrays.equals(impl.getLocationEstimate().getData(), getExtGeographicalInformation()));
        assertEquals((int) impl.getAgeOfLocationEstimate(), 15);

        assertNull(impl.getExtensionContainer());

        assertTrue(Arrays.equals(impl.getAdditionalLocationEstimate().getData(), getAddGeographicalInformation()));
        assertTrue(impl.getDeferredMTLRResponseIndicator());
        assertTrue(Arrays.equals(impl.getGeranPositioningData().getData(), getPositioningDataInformation()));
        assertTrue(Arrays.equals(impl.getUtranPositioningData().getData(), getUtranPositioningDataInfo()));
        assertEquals(impl.getCellIdOrSai().getLAIFixedLength().getMCC(), 121);
        assertEquals(impl.getCellIdOrSai().getLAIFixedLength().getMNC(), 1);
        assertEquals(impl.getCellIdOrSai().getLAIFixedLength().getLac(), 2222);
        assertTrue(impl.getSaiPresent());
        assertEquals(impl.getAccuracyFulfilmentIndicator(), AccuracyFulfilmentIndicator.requestedAccuracyFulfilled);
        assertTrue(Arrays.equals(impl.getVelocityEstimate().getData(), getVelocityEstimate()));
        assertTrue(impl.getMoLrShortCircuitIndicator());
        assertTrue(Arrays.equals(impl.getGeranGANSSpositioningData().getData(), getGeranGANSSpositioningData()));
        assertTrue(Arrays.equals(impl.getUtranGANSSpositioningData().getData(), getUtranGANSSpositioningData()));
        assertTrue(impl.getTargetServingNodeForHandover().getMscNumber().getAddress().equals("444666888"));
    }

    @Test(groups = { "functional.encode", "service.lsm" })
    public void testEncode() throws Exception {
        byte[] rawData = getEncodedData();

        ExtGeographicalInformationImpl egeo = new ExtGeographicalInformationImpl(getExtGeographicalInformation());

        ProvideSubscriberLocationResponseImpl reqInd = new ProvideSubscriberLocationResponseImpl(egeo, null, null, 15, null,
                null, false, null, false, null, null, false, null, null, null);

        AsnOutputStream asnOS = new AsnOutputStream();
        reqInd.encodeAll(asnOS);

        byte[] encodedData = asnOS.toByteArray();
        assertTrue(Arrays.equals(rawData, encodedData));

        rawData = getEncodedDataFull();

        PositioningDataInformationImpl geranPositioningData = new PositioningDataInformationImpl(
                getPositioningDataInformation());
        UtranPositioningDataInfoImpl utranPositioningData = new UtranPositioningDataInfoImpl(getUtranPositioningDataInfo());
        AddGeographicalInformationImpl additionalLocationEstimate = new AddGeographicalInformationImpl(
                getAddGeographicalInformation());
        LAIFixedLengthImpl laiFixedLength = new LAIFixedLengthImpl(121, 1, 2222);
        CellGlobalIdOrServiceAreaIdOrLAIImpl cellGlobalIdOrServiceAreaIdOrLAI = new CellGlobalIdOrServiceAreaIdOrLAIImpl(
                laiFixedLength);
        VelocityEstimateImpl velocityEstimate = new VelocityEstimateImpl(getVelocityEstimate());
        GeranGANSSpositioningDataImpl geranGANSSpositioningData = new GeranGANSSpositioningDataImpl(
                getGeranGANSSpositioningData());
        UtranGANSSpositioningDataImpl utranGANSSpositioningData = new UtranGANSSpositioningDataImpl(
                getUtranGANSSpositioningData());
        ISDNAddressStringImpl isdnNumber = new ISDNAddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN,
                "444666888");
        ServingNodeAddressImpl targetServingNodeForHandover = new ServingNodeAddressImpl(isdnNumber, true);

        reqInd = new ProvideSubscriberLocationResponseImpl(egeo, geranPositioningData, utranPositioningData, 15,
                additionalLocationEstimate, null, true, cellGlobalIdOrServiceAreaIdOrLAI, true,
                AccuracyFulfilmentIndicator.requestedAccuracyFulfilled, velocityEstimate, true, geranGANSSpositioningData,
                utranGANSSpositioningData, targetServingNodeForHandover);
        // ExtGeographicalInformation locationEstimate, PositioningDataInformation geranPositioningData,
        // UtranPositioningDataInfo utranPositioningData, Integer ageOfLocationEstimate, AddGeographicalInformation
        // additionalLocationEstimate,
        // MAPExtensionContainer extensionContainer, Boolean deferredMTLRResponseIndicator, CellGlobalIdOrServiceAreaIdOrLAI
        // cellGlobalIdOrServiceAreaIdOrLAI,
        // Boolean saiPresent, AccuracyFulfilmentIndicator accuracyFulfilmentIndicator, VelocityEstimate velocityEstimate,
        // boolean moLrShortCircuitIndicator,
        // GeranGANSSpositioningData geranGANSSpositioningData, UtranGANSSpositioningData utranGANSSpositioningData,
        // ServingNodeAddress targetServingNodeForHandover

        asnOS = new AsnOutputStream();
        reqInd.encodeAll(asnOS);

        encodedData = asnOS.toByteArray();
        assertTrue(Arrays.equals(rawData, encodedData));
    }

}
