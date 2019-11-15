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

package org.restcomm.protocols.ss7.cap.api.service.sms;

import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.primitives.CalledPartyBCDNumber;
import org.restcomm.protocols.ss7.cap.api.service.sms.primitive.SMSAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;

/**
 *
 connectSMS {PARAMETERS-BOUND : bound} OPERATION ::= {
   ARGUMENT ConnectSMSArg {bound}
   RETURN RESULT FALSE
   ERRORS {missingParameter | parameterOutOfRange | systemFailure | taskRefused | unexpectedComponentSequence | unexpectedDataValue |
     unexpectedParameter}
   CODE opcode-connectSMS}
 -- Direction: gsmSCF -> gsmSSF or gprsSSF, Timer: Tconsms
 -- This operation is used to request the smsSSF to perform the SMS processing
 -- actions to route or forward a short message to a specified destination.

 ConnectSMSArg {PARAMETERS-BOUND : bound} ::= SEQUENCE {
   callingPartysNumber         [0] SMS-AddressString OPTIONAL,
   destinationSubscriberNumber [1] CalledPartyBCDNumber {bound} OPTIONAL,
   sMSCAddress                 [2] ISDN-AddressString OPTIONAL,
   extensions                  [10] Extensions {bound} OPTIONAL,
   ...
}
 *
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface ConnectSMSRequest extends SmsMessage {

    SMSAddressString getCallingPartysNumber();

    CalledPartyBCDNumber getDestinationSubscriberNumber();

    ISDNAddressString getSMSCAddress();

    CAPExtensions getExtensions();

}