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

package org.restcomm.protocols.ss7.tcapAnsi.asn;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.EncodeException;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.UserInformation;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.UserInformationElement;
import org.restcomm.protocols.ss7.tcapAnsi.asn.UserInformationElementImpl;
import org.restcomm.protocols.ss7.tcapAnsi.asn.UserInformationImpl;
import org.testng.annotations.Test;

/**
*
* @author sergey vetyutnev
*
*/
public class UserInformationTest {

    private byte[] data = new byte[] { (byte) 253, 20, 40, 18, 6, 7, 4, 0, 0, 1, 1, 1, 1, -96, 7, 1, 2, 3, 4, 5, 6, 7 };

    private byte[] dataValue = new byte[] { 1, 2, 3, 4, 5, 6, 7 };

    @Test(groups = { "functional.decode" })
    public void testDecode() throws Exception {

        AsnInputStream asin = new AsnInputStream(data);
        int tag = asin.readTag();
        assertEquals(UserInformation._TAG_USER_INFORMATION, tag);
        assertEquals(Tag.CLASS_PRIVATE, asin.getTagClass());
        assertFalse(asin.isTagPrimitive());

        UserInformation userInformation = new UserInformationImpl();
        userInformation.decode(asin);

        assertEquals(userInformation.getUserInformationElements().length, 1);
        UserInformationElement userInformationElement = userInformation.getUserInformationElements()[0];

        assertTrue(userInformationElement.isOid());

        assertTrue(Arrays.equals(new long[] { 0, 4, 0, 0, 1, 1, 1, 1 }, userInformationElement.getOidValue()));

        assertFalse(userInformationElement.isInteger());

        assertTrue(userInformationElement.isAsn());
        assertEquals(dataValue, userInformationElement.getEncodeType());

    }

    @Test(groups = { "functional.encode" })
    public void testUserInformationEncode() throws IOException, EncodeException {

        UserInformationElement userInformationElement = new UserInformationElementImpl();

        userInformationElement.setOid(true);
        userInformationElement.setOidValue(new long[] { 0, 4, 0, 0, 1, 1, 1, 1 });

        userInformationElement.setAsn(true);
        userInformationElement.setEncodeType(dataValue);

        UserInformation userInformation = new UserInformationImpl();
        userInformation.setUserInformationElements(new UserInformationElement[] { userInformationElement });

        AsnOutputStream asnos = new AsnOutputStream();
        userInformation.encode(asnos);

        byte[] userInfData = asnos.toByteArray();

        assertTrue(Arrays.equals(data, userInfData));

    }

}
