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

package org.restcomm.protocols.ss7.map.service.mobility.authentication;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationQuintuplet;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.AuthenticationQuintupletImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.AuthenticationSetListImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.QuintupletListImpl;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class QuintupletListTest {

    private byte[] getEncodedData() {
        return new byte[] { -95, 80, 48, 78, 4, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 2, 2, 2, 2, 4, 16, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 16, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 16, 5,
                5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };
    }

    @Test
    public void testDecode() throws Exception {

        byte[] rawData = getEncodedData();
        AsnInputStream asn = new AsnInputStream(rawData);

        int tag = asn.readTag();
        QuintupletListImpl asc = new QuintupletListImpl();
        asc.decodeAll(asn);

        assertEquals(tag, AuthenticationSetListImpl._TAG_quintupletList);
        assertEquals(asn.getTagClass(), Tag.CLASS_CONTEXT_SPECIFIC);

        assertEquals(asc.getAuthenticationQuintuplets().size(), 1);

        assertTrue(Arrays.equals(asc.getAuthenticationQuintuplets().get(0).getRand(),
                AuthenticationQuintupletTest.getRandData()));
        assertTrue(Arrays.equals(asc.getAuthenticationQuintuplets().get(0).getXres(),
                AuthenticationQuintupletTest.getXresData()));
        assertTrue(Arrays.equals(asc.getAuthenticationQuintuplets().get(0).getCk(), AuthenticationQuintupletTest.getCkData()));
        assertTrue(Arrays.equals(asc.getAuthenticationQuintuplets().get(0).getIk(), AuthenticationQuintupletTest.getIkData()));
        assertTrue(Arrays.equals(asc.getAuthenticationQuintuplets().get(0).getAutn(),
                AuthenticationQuintupletTest.getAutnData()));

    }

    @Test(groups = { "functional.encode" })
    public void testEncode() throws Exception {

        AuthenticationQuintupletImpl d1 = new AuthenticationQuintupletImpl(AuthenticationQuintupletTest.getRandData(),
                AuthenticationQuintupletTest.getXresData(), AuthenticationQuintupletTest.getCkData(),
                AuthenticationQuintupletTest.getIkData(), AuthenticationQuintupletTest.getAutnData());
        ArrayList<AuthenticationQuintuplet> arr = new ArrayList<AuthenticationQuintuplet>();
        arr.add(d1);
        QuintupletListImpl asc = new QuintupletListImpl(arr);

        AsnOutputStream asnOS = new AsnOutputStream();
        asc.encodeAll(asnOS, Tag.CLASS_CONTEXT_SPECIFIC, AuthenticationSetListImpl._TAG_quintupletList);

        byte[] encodedData = asnOS.toByteArray();
        byte[] rawData = getEncodedData();
        assertTrue(Arrays.equals(rawData, encodedData));

    }
}
