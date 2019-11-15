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

package org.restcomm.protocols.ss7.map.service.lsm;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.MAPParameterFactoryImpl;
import org.restcomm.protocols.ss7.map.api.MAPParameterFactory;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSFormatIndicator;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSRequestorIDImpl;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 *
 *
 * @author amit bhayani
 *
 */
public class LCSRequestorIDTest {

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

    public byte[] getData() {
        return new byte[] { 48, 0x13, (byte) 0x80, 0x01, 0x0f, (byte) 0x81, 0x0e, 0x6e, 0x72, (byte) 0xfb, 0x1c, (byte) 0x86,
                (byte) 0xc3, 0x65, 0x6e, 0x72, (byte) 0xfb, 0x1c, (byte) 0x86, (byte) 0xc3, 0x65 };
    }

    public byte[] getDataFull() {
        return new byte[] { 48, 22, -128, 1, 15, -127, 14, 110, 114, -5, 28, -122, -61, 101, 110, 114, -5, 28, -122, -61, 101,
                -126, 1, 1 };
    }

    @Test(groups = { "functional.decode", "service.lsm" })
    public void testDecode() throws Exception {
        byte[] data = getData();

        AsnInputStream asn = new AsnInputStream(data);
        int tag = asn.readTag();
        assertEquals(tag, Tag.SEQUENCE);

        LCSRequestorIDImpl lcsRequestorID = new LCSRequestorIDImpl();
        lcsRequestorID.decodeAll(asn);

        assertEquals(lcsRequestorID.getDataCodingScheme().getCode(), 0x0f);
        assertNotNull(lcsRequestorID.getRequestorIDString());
        assertEquals(lcsRequestorID.getRequestorIDString().getString(null), "ndmgapp2ndmgapp2");

        assertNull(lcsRequestorID.getLCSFormatIndicator());

        data = getDataFull();

        asn = new AsnInputStream(data);
        tag = asn.readTag();
        assertEquals(tag, Tag.SEQUENCE);

        lcsRequestorID = new LCSRequestorIDImpl();
        lcsRequestorID.decodeAll(asn);

        assertEquals(lcsRequestorID.getDataCodingScheme().getCode(), 0x0f);
        assertNotNull(lcsRequestorID.getRequestorIDString());
        assertEquals(lcsRequestorID.getRequestorIDString().getString(null), "ndmgapp2ndmgapp2");

        assertEquals(lcsRequestorID.getLCSFormatIndicator(), LCSFormatIndicator.emailAddress);
    }

    @Test(groups = { "functional.encode", "service.lsm" })
    public void testEncode() throws Exception {
        byte[] data = getData();

        USSDString nameString = MAPParameterFactory.createUSSDString("ndmgapp2ndmgapp2");
        LCSRequestorIDImpl lcsRequestorID = new LCSRequestorIDImpl(new CBSDataCodingSchemeImpl(0x0f), nameString, null);
        AsnOutputStream asnOS = new AsnOutputStream();
        lcsRequestorID.encodeAll(asnOS);

        byte[] encodedData = asnOS.toByteArray();

        assertTrue(Arrays.equals(data, encodedData));

        data = getDataFull();

        lcsRequestorID = new LCSRequestorIDImpl(new CBSDataCodingSchemeImpl(0x0f), nameString, LCSFormatIndicator.emailAddress);
        asnOS = new AsnOutputStream();
        lcsRequestorID.encodeAll(asnOS);

        encodedData = asnOS.toByteArray();

        assertTrue(Arrays.equals(data, encodedData));
    }

    @Test(groups = { "functional.serialize", "service.lsm" })
    public void testSerialization() throws Exception {
        USSDString nameString = MAPParameterFactory.createUSSDString("ndmgapp2ndmgapp2");
        LCSRequestorIDImpl original = new LCSRequestorIDImpl(new CBSDataCodingSchemeImpl(0x0f), nameString, null);

        // serialize
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(original);
        oos.close();

        // deserialize
        byte[] pickled = out.toByteArray();
        InputStream in = new ByteArrayInputStream(pickled);
        ObjectInputStream ois = new ObjectInputStream(in);
        Object o = ois.readObject();
        LCSRequestorIDImpl copy = (LCSRequestorIDImpl) o;

        // test result
        assertEquals(copy, original);
    }
}
