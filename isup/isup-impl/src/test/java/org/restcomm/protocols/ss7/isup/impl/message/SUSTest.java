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
 * Start time:09:26:46 2009-04-22<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski
 *         </a>
 *
 */
package org.restcomm.protocols.ss7.isup.impl.message;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import org.restcomm.protocols.ss7.isup.impl.message.AbstractISUPMessage;
import org.restcomm.protocols.ss7.isup.message.ISUPMessage;
import org.restcomm.protocols.ss7.isup.message.SuspendMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.CallReference;
import org.testng.annotations.Test;

/**
 * Start time:09:26:46 2009-04-22<br>
 * Project: mobicents-isup-stack<br>
 * Test for ACM
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class SUSTest extends MessageHarness {

    @Test(groups = { "functional.encode", "functional.decode", "message" })
    public void testTwo_Params() throws Exception {

        byte[] message = getDefaultBody();


        SuspendMessage msg =  super.messageFactory.createSUS();
        ((AbstractISUPMessage) msg).decode(message, messageFactory,parameterFactory);

        assertNotNull(msg.getSuspendResumeIndicators());
        assertEquals(msg.getSuspendResumeIndicators().isSuspendResumeIndicator(), true);
        
        assertNotNull(msg.getCallReference());
        assertEquals(msg.getCallReference().getCallIdentity(), 1436);
        assertEquals(msg.getCallReference().getSignalingPointCode(), 9743);
    }

    protected byte[] getDefaultBody() {
        byte[] message = {
                // CIC
                0x0C, (byte) 0x0B,
                SuspendMessage.MESSAGE_CODE, 
                    //suspend/resume
                    0x01,
                    //pointer
                    0x01,
                    CallReference._PARAMETER_CODE,
                        //len
                        0x05,
                            0x00,
                            0x05,
                            (byte) 0x9c,
                            0x0f,
                            0x26,
                0x00
                
        };
        return message;
    }

    protected ISUPMessage getDefaultMessage() {
        return super.messageFactory.createSUS();
    }
}
