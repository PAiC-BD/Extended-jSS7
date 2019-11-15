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

package org.restcomm.protocols.ss7.sccp.message;

import org.restcomm.protocols.ss7.sccp.parameter.Credit;
import org.restcomm.protocols.ss7.sccp.parameter.HopCounter;
import org.restcomm.protocols.ss7.sccp.parameter.Importance;
import org.restcomm.protocols.ss7.sccp.parameter.LocalReference;
import org.restcomm.protocols.ss7.sccp.parameter.ProtocolClass;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;

/**
 *
 * This interface represents a SCCP connection request message for connection-oriented protocol classes 2 and 3.
 *
 */
public interface SccpConnCrMessage extends SccpConnMessage, SccpAddressedMessage {

    LocalReference getSourceLocalReferenceNumber();
    void setSourceLocalReferenceNumber(LocalReference number);

    SccpAddress getCalledPartyAddress();
    void setCalledPartyAddress(SccpAddress address);

    SccpAddress getCallingPartyAddress();
    void setCallingPartyAddress(SccpAddress address);

    ProtocolClass getProtocolClass();
    void setProtocolClass(ProtocolClass value);

    Credit getCredit();
    void setCredit(Credit value);

    byte[] getUserData();
    void setUserData(byte[] data);

    HopCounter getHopCounter();
    void setHopCounter(HopCounter counter);
    boolean reduceHopCounter();

    Importance getImportance();
    void setImportance(Importance importance);

    boolean getSccpCreatesSls();
}
