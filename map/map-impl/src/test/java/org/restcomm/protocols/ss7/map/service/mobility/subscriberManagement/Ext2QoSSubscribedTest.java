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

import static org.testng.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javolution.xml.XMLObjectReader;
import javolution.xml.XMLObjectWriter;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Ext2QoSSubscribed_SourceStatisticsDescriptor;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRateExtended;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_DeliveryOfErroneousSdus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_DeliveryOrder;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_ResidualBER;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_SduErrorRatio;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_TrafficClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_TrafficHandlingPriority;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.Ext2QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRateExtendedImpl;
import org.testng.annotations.Test;

/**
*
* @author sergey vetyutnev
*
*/
public class Ext2QoSSubscribedTest {

    public byte[] getData1() {
        return new byte[] { 4, 3, 17, 74, (byte) 250 };
    };

    public byte[] getData2() {
        return new byte[] { 4, 3, 0, (byte) 142, 0 };
    };

    @Test(groups = { "functional.decode", "mobility.subscriberManagement" })
    public void testDecode() throws Exception {
        byte[] data = this.getData1();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        Ext2QoSSubscribedImpl prim = new Ext2QoSSubscribedImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertEquals(prim.getSourceStatisticsDescriptor(), Ext2QoSSubscribed_SourceStatisticsDescriptor.speech);
        assertTrue(prim.isOptimisedForSignallingTraffic());
        assertEquals(prim.getMaximumBitRateForDownlinkExtended().getBitRate(), 16000);
        assertEquals(prim.getGuaranteedBitRateForDownlinkExtended().getBitRate(), 256000);
        assertFalse(prim.getGuaranteedBitRateForDownlinkExtended().isUseNonextendedValue());


        data = this.getData2();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new Ext2QoSSubscribedImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertEquals(prim.getSourceStatisticsDescriptor(), Ext2QoSSubscribed_SourceStatisticsDescriptor.unknown);
        assertFalse(prim.isOptimisedForSignallingTraffic());
        assertEquals(prim.getMaximumBitRateForDownlinkExtended().getBitRate(), 84000);
        assertEquals(prim.getGuaranteedBitRateForDownlinkExtended().getBitRate(), 0);
        assertTrue(prim.getGuaranteedBitRateForDownlinkExtended().isUseNonextendedValue());
    }

    @Test(groups = { "functional.encode", "mobility.subscriberManagement" })
    public void testEncode() throws Exception {
        ExtQoSSubscribed_BitRateExtended maximumBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(16000, false);
        ExtQoSSubscribed_BitRateExtended guaranteedBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(256000, false);
        Ext2QoSSubscribedImpl prim = new Ext2QoSSubscribedImpl(Ext2QoSSubscribed_SourceStatisticsDescriptor.speech, true, maximumBitRateForDownlinkExtended,
                guaranteedBitRateForDownlinkExtended);
//        Ext2QoSSubscribed_SourceStatisticsDescriptor sourceStatisticsDescriptor, boolean optimisedForSignallingTraffic,
//        ExtQoSSubscribed_BitRateExtended maximumBitRateForDownlinkExtended, ExtQoSSubscribed_BitRateExtended guaranteedBitRateForDownlinkExtended

        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);

        assertEquals(asn.toByteArray(), this.getData1());


        maximumBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(84000, false);
        guaranteedBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(0, true);
        prim = new Ext2QoSSubscribedImpl(Ext2QoSSubscribed_SourceStatisticsDescriptor.unknown, false, maximumBitRateForDownlinkExtended,
                guaranteedBitRateForDownlinkExtended);

        asn = new AsnOutputStream();
        prim.encodeAll(asn);

        assertEquals(asn.toByteArray(), this.getData2());
    }
    
    @Test(groups = { "functional.xml.serialize", "subscriberInformation" })
    public void testXMLSerialize() throws Exception {

        ExtQoSSubscribed_BitRateExtended maximumBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(16000, false);
        ExtQoSSubscribed_BitRateExtended guaranteedBitRateForDownlinkExtended = new ExtQoSSubscribed_BitRateExtendedImpl(256000, false);
        Ext2QoSSubscribedImpl original = new Ext2QoSSubscribedImpl(Ext2QoSSubscribed_SourceStatisticsDescriptor.speech, true, maximumBitRateForDownlinkExtended,
                guaranteedBitRateForDownlinkExtended);

        // Writes the area to a file.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLObjectWriter writer = XMLObjectWriter.newInstance(baos);
        writer.setIndentation("\t"); // Optional (use tabulation for indentation).
        writer.write(original, "ext2QoSSubscribed", Ext2QoSSubscribedImpl.class);
        writer.close();

        byte[] rawData = baos.toByteArray();
        String serializedEvent = new String(rawData);

        System.out.println(serializedEvent);

        ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
        XMLObjectReader reader = XMLObjectReader.newInstance(bais);
        Ext2QoSSubscribedImpl copy = reader.read("ext2QoSSubscribed", Ext2QoSSubscribedImpl.class);

        assertEquals(copy.getGuaranteedBitRateForDownlinkExtended().getBitRate(), original.getGuaranteedBitRateForDownlinkExtended().getBitRate());
        assertEquals(copy.isOptimisedForSignallingTraffic(), original.isOptimisedForSignallingTraffic());
        assertEquals(copy.getMaximumBitRateForDownlinkExtended().getBitRate(), original.getMaximumBitRateForDownlinkExtended().getBitRate());
        assertEquals(copy.getSourceStatisticsDescriptor(), original.getSourceStatisticsDescriptor());
    }

}
