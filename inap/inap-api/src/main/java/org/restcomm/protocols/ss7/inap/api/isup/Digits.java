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

package org.restcomm.protocols.ss7.inap.api.isup;

import java.io.Serializable;

import org.restcomm.protocols.ss7.inap.api.INAPException;
import org.restcomm.protocols.ss7.isup.message.parameter.GenericDigits;
import org.restcomm.protocols.ss7.isup.message.parameter.GenericNumber;

/**
*
<code>
ISUP GenericNumber & GenericDigits wrapper

Digits {PARAMETERS-BOUND : bound} ::= OCTET STRING (SIZE
bound.&minDigitsLength..bound.&maxDigitsLength))
-- Indicates the address signalling digits.
-- Refer to the ITU-T Recommendation Q.763 Generic Number & Generic Digits parameters for encoding.
-- The coding of the subfields 'NumberQualifier' in Generic Number and 'TypeOfDigits' in
-- Generic Digits are irrelevant to the INAP;
-- the ASN.1 tags are sufficient to identify the parameter.
-- The ISUP format does not allow to exclude these subfields,
-- therefore the value is network operator specific.
-- The following parameters should use Generic Number:
-- CorrelationID for AssistRequestInstructions,
-- AssistingSSPIPRoutingAddress for EstablishTemporaryConnection,
-- calledAddressValue for all occurrences,callingAddressValue for all occurrences.
-- The following parameters should use Generic Digits: prefix, all
-- other CorrelationID occurrences, dialledNumber filtering criteria,
-- callingLineID filtering criteria, lineID for ResourceID
-- type, digitResponse for ReceivedInformationArg,
-- iNServiceControlLow / iNServiceControlHighfor MidCallInfoType,
-- iNServiceControlCode for MidCallInfo.
</code>

*
* @author sergey vetyutnev
*
*/
public interface Digits extends Serializable {

    byte[] getData();

    GenericDigits getGenericDigits() throws INAPException;

    GenericNumber getGenericNumber() throws INAPException;

    void setData(byte[] data);

    void setGenericDigits(GenericDigits genericDigits) throws INAPException;

    void setGenericNumber(GenericNumber genericNumber) throws INAPException;

    boolean getIsGenericDigits();

    boolean getIsGenericNumber();

    /**
     * Set that Digits carries GenericDigits element Attention: this value must be set after primitive decoding !!!!
     */
    void setIsGenericDigits();

    /**
     * Set that Digits carries GenericNumber element Attention: this value must be set after primitive decoding !!!!
     */
    void setIsGenericNumber();

}
