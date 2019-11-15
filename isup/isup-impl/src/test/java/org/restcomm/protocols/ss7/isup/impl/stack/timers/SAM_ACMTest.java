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

package org.restcomm.protocols.ss7.isup.impl.stack.timers;

import org.restcomm.protocols.ss7.isup.ISUPTimeoutEvent;
import org.restcomm.protocols.ss7.isup.message.AddressCompleteMessage;
import org.restcomm.protocols.ss7.isup.message.ISUPMessage;
import org.restcomm.protocols.ss7.isup.message.SubsequentAddressMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.BackwardCallIndicators;
import org.restcomm.protocols.ss7.isup.message.parameter.CircuitIdentificationCode;
import org.restcomm.protocols.ss7.isup.message.parameter.SubsequentNumber;

/**
 * @author baranowb
 *
 */
public class SAM_ACMTest extends SingleTimers {

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.impl.stack.timers.SingleTimers#getT()
     */

    protected long getT() {
        return ISUPTimeoutEvent.T7_DEFAULT;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.impl.stack.timers.SingleTimers#getT_ID()
     */

    protected int getT_ID() {
        return ISUPTimeoutEvent.T7;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.impl.stack.timers.EventTestHarness#getRequest()
     */

    protected ISUPMessage getRequest() {
        SubsequentAddressMessage msg = super.provider.getMessageFactory().createSAM(1);

        SubsequentNumber sn = super.provider.getParameterFactory().createSubsequentNumber();
        sn.setAddress("11");
        msg.setSubsequentNumber(sn);

        return msg;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.impl.stack.timers.EventTestHarness#getAnswer()
     */

    protected ISUPMessage getAnswer() {
        AddressCompleteMessage ans = super.provider.getMessageFactory().createACM();
        BackwardCallIndicators bci = super.provider.getParameterFactory().createBackwardCallIndicators();
        ans.setBackwardCallIndicators(bci);
        CircuitIdentificationCode cic = super.provider.getParameterFactory().createCircuitIdentificationCode();
        cic.setCIC(1);
        ans.setCircuitIdentificationCode(cic);
        return ans;
    }
}
