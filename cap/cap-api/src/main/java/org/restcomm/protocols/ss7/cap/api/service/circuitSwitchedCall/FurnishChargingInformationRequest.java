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

import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.FCIBCCCAMELsequence1;

/**
 *
<code>
furnishChargingInformation {PARAMETERS-BOUND : bound} OPERATION ::= {
  ARGUMENT FurnishChargingInformationArg {bound}
  RETURN RESULT FALSE
  ERRORS {missingParameter | taskRefused | unexpectedComponentSequence | unexpectedDataValue | unexpectedParameter | unknownLegID}
  CODE opcode-furnishChargingInformation
}
-- Direction: gsmSCF -> gsmSSF, Timer: T fci
-- This operation is used to request the gsmSSF to generate, register a call record
-- or to include some information in the default call record.
-- The registered call record is intended for off line charging of the call.

FurnishChargingInformationArg {PARAMETERS-BOUND : bound} ::= FCIBillingChargingCharacteristics{bound}

FCIBillingChargingCharacteristics {PARAMETERS-BOUND : bound} ::= OCTET STRING (SIZE( bound.&minFCIBillingChargingLength .. bound.&maxFCIBillingChargingLength))
(CONSTRAINED BY {
-- shall be the result of the BER-encoded value of type
-- CAMEL-FCIBillingChargingCharacteristics {bound}})
-- This parameter indicates the billing and/or charging characteristics.
-- The violation of the UserDefinedConstraint shall be handled as an ASN.1 syntax error.

minFCIBillingChargingLength ::= 5
maxFCIBillingChargingLength ::= 255

CAMEL-FCIBillingChargingCharacteristics {PARAMETERS-BOUND : bound} ::= CHOICE{
  fCIBCCCAMELsequence1 [0] SEQUENCE {
    freeFormatData       [0] OCTET STRING (SIZE( bound.&minFCIBillingChargingDataLength .. bound.&maxFCIBillingChargingDataLength)),
    partyToCharge        [1] SendingSideID DEFAULT sendingSideID: leg1,
    appendFreeFormatData [2] AppendFreeFormatData DEFAULT overwrite,
    ...
  }
}
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface FurnishChargingInformationRequest extends CircuitSwitchedCallMessage {

    FCIBCCCAMELsequence1 getFCIBCCCAMELsequence1();

}