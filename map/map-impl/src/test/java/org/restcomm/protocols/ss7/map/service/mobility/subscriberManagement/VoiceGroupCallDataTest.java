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
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.BitSetStrictLength;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AdditionalInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AdditionalSubscriptions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GroupId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LongGroupId;
import org.restcomm.protocols.ss7.map.primitives.MAPExtensionContainerTest;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AdditionalInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AdditionalSubscriptionsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GroupIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LongGroupIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.VoiceGroupCallDataImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class VoiceGroupCallDataTest {

    public byte[] getData() {
        return new byte[] { 48, 60, 4, 3, -1, -1, -1, 48, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3,
                42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, 3, 2, 5, -96, -128, 2, 7, -128,
                -127, 4, -11, -1, -1, -1 };
    };

    public byte[] getData2() {
        return new byte[] { 48, 54, 4, 3, -12, -1, -1, 48, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6,
                3, 42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, 3, 2, 5, -96, -128, 2, 7, -128 };
    };

    public byte[] getData3() {
        return new byte[] { 48, 60, 4, 3, -1, -1, -1, 48, 39, -96, 32, 48, 10, 6, 3, 42, 3, 4, 11, 12, 13, 14, 15, 48, 5, 6, 3,
                42, 3, 6, 48, 11, 6, 3, 42, 3, 5, 21, 22, 23, 24, 25, 26, -95, 3, 31, 32, 33, 3, 2, 5, -96, -128, 2, 7, -128,
                -127, 4, -11, -1, -1, -1 };
    };

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {
        // Option 1
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        VoiceGroupCallDataImpl prim = new VoiceGroupCallDataImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.SEQUENCE);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertTrue(prim.getGroupId().getGroupId().equals(""));
        assertTrue(prim.getLongGroupId().getLongGroupId().equals("5"));
        assertNotNull(prim.getExtensionContainer());
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(prim.getExtensionContainer()));
        assertTrue(prim.getAdditionalSubscriptions().getEmergencyReset());
        assertFalse(prim.getAdditionalSubscriptions().getEmergencyUplinkRequest());
        assertTrue(prim.getAdditionalSubscriptions().getPrivilegedUplinkRequest());
        assertNotNull(prim.getAdditionalInfo());
        assertTrue(prim.getAdditionalInfo().getData().get(0));

        // Option 2
        data = this.getData2();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new VoiceGroupCallDataImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.SEQUENCE);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertTrue(prim.getGroupId().getGroupId().equals("4"));
        assertNull(prim.getLongGroupId());
        assertNotNull(prim.getExtensionContainer());
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(prim.getExtensionContainer()));
        assertTrue(prim.getAdditionalSubscriptions().getEmergencyReset());
        assertFalse(prim.getAdditionalSubscriptions().getEmergencyUplinkRequest());
        assertTrue(prim.getAdditionalSubscriptions().getPrivilegedUplinkRequest());
        assertNotNull(prim.getAdditionalInfo());
        assertTrue(prim.getAdditionalInfo().getData().get(0));

        // Option 3
        data = this.getData3();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new VoiceGroupCallDataImpl();
        prim.decodeAll(asn);

        assertEquals(tag, Tag.SEQUENCE);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);

        assertTrue(prim.getGroupId().getGroupId().equals(""));
        assertTrue(prim.getLongGroupId().getLongGroupId().equals("5"));
        assertNotNull(prim.getExtensionContainer());
        assertTrue(MAPExtensionContainerTest.CheckTestExtensionContainer(prim.getExtensionContainer()));
        assertTrue(prim.getAdditionalSubscriptions().getEmergencyReset());
        assertFalse(prim.getAdditionalSubscriptions().getEmergencyUplinkRequest());
        assertTrue(prim.getAdditionalSubscriptions().getPrivilegedUplinkRequest());
        assertNotNull(prim.getAdditionalInfo());
        assertTrue(prim.getAdditionalInfo().getData().get(0));

    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {
        // Option 1
        GroupId groupId = new GroupIdImpl("4");
        MAPExtensionContainer extensionContainer = MAPExtensionContainerTest.GetTestExtensionContainer();
        LongGroupId longGroupId = new LongGroupIdImpl("5");
        AdditionalSubscriptions additionalSubscriptions = new AdditionalSubscriptionsImpl(true, false, true);
        BitSetStrictLength b = new BitSetStrictLength(1);
        b.set(0);
        AdditionalInfo additionalInfo = new AdditionalInfoImpl(b);

        VoiceGroupCallDataImpl prim = new VoiceGroupCallDataImpl(groupId, extensionContainer, additionalSubscriptions,
                additionalInfo, longGroupId);

        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));

        // Option 2
        prim = new VoiceGroupCallDataImpl(groupId, extensionContainer, additionalSubscriptions, additionalInfo, null);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData2()));

        // Option 3
        prim = new VoiceGroupCallDataImpl(null, extensionContainer, additionalSubscriptions, additionalInfo, longGroupId);
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData3()));
    }

}
