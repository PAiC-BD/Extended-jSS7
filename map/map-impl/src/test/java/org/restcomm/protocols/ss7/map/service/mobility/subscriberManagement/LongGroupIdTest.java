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
import static org.testng.Assert.assertTrue;

import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LongGroupIdImpl;
import org.testng.annotations.Test;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class LongGroupIdTest {

    public byte[] getData() {
        return new byte[] { 4, 4, 33, 67, 101, -121 };
    };

    public byte[] getData2() {
        return new byte[] { 4, 4, 33, 67, 101, -9 };
    };

    public byte[] getData3() {
        return new byte[] { 4, 4, 33, 67, 101, -1 };
    };

    public byte[] getData4() {
        return new byte[] { 4, 4, 33, 67, -11, -1 };
    };

    public byte[] getData5() {
        return new byte[] { 4, 4, 33, 67, -1, -1 };
    };

    public byte[] getData6() {
        return new byte[] { 4, 4, 33, -13, -1, -1 };
    };

    public byte[] getData7() {
        return new byte[] { 4, 4, 33, -1, -1, -1 };
    };

    public byte[] getData8() {
        return new byte[] { 4, 4, -15, -1, -1, -1 };
    };

    @Test(groups = { "functional.decode", "primitives" })
    public void testDecode() throws Exception {
        // option 1
        byte[] data = this.getData();
        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        LongGroupIdImpl prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("12345678"));

        // option 2
        data = this.getData2();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("1234567"));

        // option 3
        data = this.getData3();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("123456"));

        // option 4
        data = this.getData4();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("12345"));

        // option 5
        data = this.getData5();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("1234"));

        // option 6
        data = this.getData6();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("123"));

        // option 7
        data = this.getData7();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("12"));

        // option 8
        data = this.getData8();
        asn = new AsnInputStream(data);
        tag = asn.readTag();
        prim = new LongGroupIdImpl();
        prim.decodeAll(asn);
        assertEquals(tag, Tag.STRING_OCTET);
        assertEquals(asn.getTagClass(), Tag.CLASS_UNIVERSAL);
        assertTrue(prim.getLongGroupId().equals("1"));

    }

    @Test(groups = { "functional.encode", "primitives" })
    public void testEncode() throws Exception {
        // option 1
        LongGroupIdImpl prim = new LongGroupIdImpl("12345678");
        AsnOutputStream asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData()));

        // option 2
        prim = new LongGroupIdImpl("1234567");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData2()));

        // option 3
        prim = new LongGroupIdImpl("123456");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData3()));

        // option 4
        prim = new LongGroupIdImpl("12345");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData4()));

        // option 5
        prim = new LongGroupIdImpl("1234");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData5()));

        // option 6
        prim = new LongGroupIdImpl("123");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData6()));

        // option 7
        prim = new LongGroupIdImpl("12");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData7()));

        // option 8
        prim = new LongGroupIdImpl("1");
        asn = new AsnOutputStream();
        prim.encodeAll(asn);
        assertTrue(Arrays.equals(asn.toByteArray(), this.getData8()));
    }

}
