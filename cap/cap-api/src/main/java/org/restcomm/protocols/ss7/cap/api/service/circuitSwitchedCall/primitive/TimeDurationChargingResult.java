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

package org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive;

import java.io.Serializable;

import org.restcomm.protocols.ss7.cap.api.primitives.AChChargingAddress;
import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.primitives.ReceivingSideID;

/**
 *
<code>
timeDurationChargingResult [0] SEQUENCE {
  partyToCharge       [0] ReceivingSideID,
  timeInformation     [1] TimeInformation,
  legActive           [2] BOOLEAN DEFAULT TRUE,
  callLegReleasedAtTcpExpiry   [3] NULL OPTIONAL,
  extensions          [4] Extensions {bound} OPTIONAL,
  aChChargingAddress  [5] AChChargingAddress {bound} DEFAULT legID:receivingSideID:leg1,
  ...
}
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface TimeDurationChargingResult extends Serializable {

    ReceivingSideID getPartyToCharge();

    TimeInformation getTimeInformation();

    boolean getLegActive();

    boolean getCallLegReleasedAtTcpExpiry();

    CAPExtensions getExtensions();

    AChChargingAddress getAChChargingAddress();

}