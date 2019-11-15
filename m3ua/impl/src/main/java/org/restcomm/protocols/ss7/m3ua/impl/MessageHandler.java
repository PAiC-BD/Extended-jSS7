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
package org.restcomm.protocols.ss7.m3ua.impl;

import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSM;
import org.restcomm.protocols.ss7.m3ua.message.MessageClass;
import org.restcomm.protocols.ss7.m3ua.message.MessageType;
import org.restcomm.protocols.ss7.m3ua.message.mgmt.Error;
import org.restcomm.protocols.ss7.m3ua.parameter.ErrorCode;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;

/**
 *
 * @author amit bhayani
 *
 */
public abstract class MessageHandler {

    protected AspFactoryImpl aspFactoryImpl = null;

    public MessageHandler(AspFactoryImpl aspFactoryImpl) {
        this.aspFactoryImpl = aspFactoryImpl;
    }

    protected void sendError(RoutingContext rc, ErrorCode errorCode) {
        Error error = (Error) this.aspFactoryImpl.messageFactory.createMessage(MessageClass.MANAGEMENT, MessageType.ERROR);
        error.setErrorCode(errorCode);
        if (rc != null) {
            error.setRoutingContext(rc);
        }
        this.aspFactoryImpl.write(error);
    }

    /**
     * Get's the ASP for any ASP Traffic Maintenance, Management, Signalling Network Management and Transfer m3ua message's
     * received which has null Routing Context
     *
     * @return
     */
    protected AspImpl getAspForNullRc() {
        // We know if null RC, ASP cannot be shared and AspFactory will
        // have only one ASP

        AspImpl aspImpl = (AspImpl) this.aspFactoryImpl.aspList.get(0);

        if (this.aspFactoryImpl.aspList.size() > 1) {
            // verify that AS to which this ASP is added is also having null
            // RC or this asp is not shared by any other AS in which case we
            // know messages are intended for same AS

            ErrorCode errorCodeObj = this.aspFactoryImpl.parameterFactory.createErrorCode(ErrorCode.Invalid_Routing_Context);
            sendError(null, errorCodeObj);
            return null;
        }

        return aspImpl;
    }

    protected FSM getAspFSMForRxPayload(AspImpl aspImpl) {
        FSM fsm = null;
        if (aspFactoryImpl.getFunctionality() == Functionality.AS
                || (aspFactoryImpl.getFunctionality() == Functionality.SGW && aspFactoryImpl.getExchangeType() == ExchangeType.DE)
                || (aspFactoryImpl.getFunctionality() == Functionality.IPSP && aspFactoryImpl.getExchangeType() == ExchangeType.DE)
                || (aspFactoryImpl.getFunctionality() == Functionality.IPSP
                        && aspFactoryImpl.getExchangeType() == ExchangeType.SE && aspFactoryImpl.getIpspType() == IPSPType.CLIENT)) {
            fsm = aspImpl.getLocalFSM();

        } else {
            fsm = aspImpl.getPeerFSM();
        }

        return fsm;
    }

}
