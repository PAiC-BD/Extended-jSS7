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
 * Start time:16:20:47 2009-04-26<br>
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
import org.restcomm.protocols.ss7.isup.impl.message.parameter.OptionalBackwardCallIndicatorsImpl;
import org.testng.annotations.Test;

/**
 * Start time:16:20:47 2009-04-26<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class OptionalBackwardCallIndicatorsTest extends ParameterHarness {

    private static final int _TURN_ON = 1;
    private static final int _TURN_OFF = 0;

    public OptionalBackwardCallIndicatorsTest() {
        super();
        super.goodBodies.add(new byte[] { 8 });
        super.badBodies.add(new byte[] { 8, 8 });
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        OptionalBackwardCallIndicatorsImpl bci = new OptionalBackwardCallIndicatorsImpl();

        bci.decode(getBody(OptionalBackwardCallIndicatorsImpl._IBII_AVAILABLE,
                OptionalBackwardCallIndicatorsImpl._CDI_NO_INDICATION,
                OptionalBackwardCallIndicatorsImpl._SSIR_NO_ADDITIONAL_INFO, OptionalBackwardCallIndicatorsImpl._MLLPUI_USER));
        String[] methodNames = { "isInbandInformationIndicator", "isCallDiversionMayOccurIndicator",
                "isSimpleSegmentationIndicator", "isMllpUserIndicator" };
        Object[] expectedValues = { OptionalBackwardCallIndicatorsImpl._IBII_AVAILABLE,
                OptionalBackwardCallIndicatorsImpl._CDI_NO_INDICATION,
                OptionalBackwardCallIndicatorsImpl._SSIR_NO_ADDITIONAL_INFO, OptionalBackwardCallIndicatorsImpl._MLLPUI_USER };
        super.testValues(bci, methodNames, expectedValues);
    }

    private byte[] getBody(boolean ibiiAvailable, boolean cdiNoIndication, boolean ssirNoAdditionalInfo, boolean mllpuiUser) {
        byte b = (byte) ((ibiiAvailable ? _TURN_ON : _TURN_OFF));
        b |= ((cdiNoIndication ? _TURN_ON : _TURN_OFF) << 1);
        b |= ((ssirNoAdditionalInfo ? _TURN_ON : _TURN_OFF) << 2);
        b |= ((mllpuiUser ? _TURN_ON : _TURN_OFF) << 3);
        return new byte[] { b };
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new OptionalBackwardCallIndicatorsImpl();
    }

}
