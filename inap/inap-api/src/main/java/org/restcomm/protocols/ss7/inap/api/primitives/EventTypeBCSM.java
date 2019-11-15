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

package org.restcomm.protocols.ss7.inap.api.primitives;

/**
*
<code>
EventTypeBCSM ::= ENUMERATED {
origAttemptAuthorized (1),
collectedInfo (2),
analysedInformation (3),
routeSelectFailure (4),
oCalledPartyBusy (5),
oNoAnswer (6),
oAnswer (7),
oMidCall (8),
oDisconnect (9),
oAbandon (10),
termAttemptAuthorized (12),
tBusy (13),
tNoAnswer (14),
tAnswer (15),
tMidCall (16),
tDisconnect (17),
tAbandon (18),
oTermSeized (19),
oSuspended (20),
tSuspended (21),
origAttempt (22),
termAttempt (23),
oReAnswer (24),
tReAnswer (25),
facilitySelectedAndAvailable (26),
callAccepted (27)
}
-- Indicates the BCSM detection point event.
-- Refer to Q.1224 for additional information on the events.
-- Values origAttempt and termAttempt can only be used for TDPs
</code>

*
* @author sergey vetyutnev
*
*/
public enum EventTypeBCSM {
    origAttemptAuthorized(1), collectedInfo(2), analyzedInformation(3), routeSelectFailure(4), oCalledPartyBusy(5), oNoAnswer(6), oAnswer(7), oMidCall(8), oDisconnect(
            9), oAbandon(10), termAttemptAuthorized(12), tBusy(13), tNoAnswer(14), tAnswer(15), tMidCall(16), tDisconnect(17), tAbandon(18), oTermSeized(19), oSuspended(
            20), tSuspended(21), origAttempt(22), termAttempt(23), oReAnswer(24), tReAnswer(25), facilitySelectedAndAvailable(26), callAccepted(27);

    private int code;

    private EventTypeBCSM(int code) {
        this.code = code;
    }

    public static EventTypeBCSM getInstance(int code) {
        switch (code) {
        case 1:
            return EventTypeBCSM.origAttemptAuthorized;
        case 2:
            return EventTypeBCSM.collectedInfo;
        case 3:
            return EventTypeBCSM.analyzedInformation;
        case 4:
            return EventTypeBCSM.routeSelectFailure;
        case 5:
            return EventTypeBCSM.oCalledPartyBusy;
        case 6:
            return EventTypeBCSM.oNoAnswer;
        case 7:
            return EventTypeBCSM.oAnswer;
        case 8:
            return EventTypeBCSM.oMidCall;
        case 9:
            return EventTypeBCSM.oDisconnect;
        case 10:
            return EventTypeBCSM.oAbandon;
        case 12:
            return EventTypeBCSM.termAttemptAuthorized;
        case 13:
            return EventTypeBCSM.tBusy;
        case 14:
            return EventTypeBCSM.tNoAnswer;
        case 15:
            return EventTypeBCSM.tAnswer;
        case 16:
            return EventTypeBCSM.tMidCall;
        case 17:
            return EventTypeBCSM.tDisconnect;
        case 18:
            return EventTypeBCSM.tAbandon;
        case 19:
            return EventTypeBCSM.oTermSeized;
        case 20:
            return EventTypeBCSM.oSuspended;
        case 21:
            return EventTypeBCSM.tSuspended;
        case 22:
            return EventTypeBCSM.origAttempt;
        case 23:
            return EventTypeBCSM.termAttempt;
        case 24:
            return EventTypeBCSM.oReAnswer;
        case 25:
            return EventTypeBCSM.tReAnswer;
        case 26:
            return EventTypeBCSM.facilitySelectedAndAvailable;
        case 27:
            return EventTypeBCSM.callAccepted;
        default:
            return null;
        }
    }

    public int getCode() {
        return this.code;
    }
}
