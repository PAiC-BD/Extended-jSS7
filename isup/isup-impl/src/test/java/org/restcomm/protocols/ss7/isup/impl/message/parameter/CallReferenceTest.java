/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

/**
 * Start time:14:11:03 2009-04-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski
 *         </a>
 *
 */
package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.CallReferenceImpl;
import org.testng.annotations.Test;

/**
 * Start time:14:11:03 2009-04-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class CallReferenceTest extends ParameterHarness {

    /**
     * @throws IOException
     */
    public CallReferenceTest() throws IOException {
        super.badBodies.add(new byte[1]);
        super.badBodies.add(new byte[2]);
        super.badBodies.add(new byte[3]);
        super.badBodies.add(new byte[4]);
        super.badBodies.add(new byte[6]);

        super.goodBodies.add(getBody2());

    }

    private byte[] getBody1() throws IOException {

        // we will use odd number of digits, so we leave zero as MSB
        byte[] body = new byte[5];
        body[0] = 12;
        body[1] = 73;
        body[2] = 120;
        body[3] = 73;
        body[4] = 120;

        return body;
    }

    private byte[] getBody2() throws IOException {

        // we will use odd number of digits, so we leave zero as MSB
        byte[] body = new byte[5];
        body[0] = 12;
        body[1] = 73;
        body[2] = 120;
        body[3] = 73;
        // one MSB will be ignored.
        body[4] = 120 & 0x3F;

        return body;
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        CallReferenceImpl cr = new CallReferenceImpl();
        cr.decode(getBody1());
        String[] methodNames = { "getCallIdentity", "getSignalingPointCode" };
        Object[] expectedValues = { 805240, 14409 };
        super.testValues(cr, methodNames, expectedValues);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new CallReferenceImpl();
    }

}
