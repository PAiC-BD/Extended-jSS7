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

package org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall;

import java.util.ArrayList;

import org.restcomm.protocols.ss7.cap.api.primitives.BCSMEvent;
import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;

/**
 *
<code>
requestReportBCSMEvent {PARAMETERS-BOUND : bound} OPERATION ::= {
  ARGUMENT RequestReportBCSMEventArg {bound}
  RETURN RESULT FALSE
  ERRORS {missingParameter | parameterOutOfRange | systemFailure | taskRefused | unexpectedComponentSequence |
          unexpectedDataValue | unexpectedParameter | unknownLegID}
  CODE opcode-requestReportBCSMEvent
}
-- Direction: gsmSCF -> gsmSSF, Timer: Trrb
-- This operation is used to request the gsmSSF to monitor for a call-related event
-- (e.g. BCSM events such as O_Busy or O_No_Answer) and to send a notification
-- to the gsmSCF when the event is detected.
-- -- NOTE:
-- Every EDP must be explicitly armed by the gsmSCF via a RequestReportBCSMEvent operation.
-- No implicit arming of EDPs at the gsmSSF after reception of any operation (different
-- from RequestReportBCSMEvent) from the gsmSCF is allowed.

RequestReportBCSMEventArg {PARAMETERS-BOUND : bound} ::= SEQUENCE {
  bcsmEvents     [0] SEQUENCE SIZE(1..bound.&numOfBCSMEvents) OF BCSMEvent {bound},
  extensions     [2] Extensions {bound} OPTIONAL,
  ...
}
-- Indicates the BCSM related events for notification.

numOfBCSMEvents = 30
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface RequestReportBCSMEventRequest extends CircuitSwitchedCallMessage {

    ArrayList<BCSMEvent> getBCSMEventList();

    CAPExtensions getExtensions();

}
