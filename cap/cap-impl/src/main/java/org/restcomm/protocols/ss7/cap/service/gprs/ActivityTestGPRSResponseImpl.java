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
package org.restcomm.protocols.ss7.cap.service.gprs;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPMessageType;
import org.restcomm.protocols.ss7.cap.api.CAPOperationCode;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.service.gprs.ActivityTestGPRSResponse;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class ActivityTestGPRSResponseImpl extends GprsMessageImpl implements ActivityTestGPRSResponse {

    public static final String _PrimitiveName = "ActivityTestGPRSResponse";

    @Override
    public CAPMessageType getMessageType() {
        return CAPMessageType.activityTestGPRS_Response;
    }

    @Override
    public int getOperationCode() {
        return CAPOperationCode.activityTestGPRS;
    }

    @Override
    public int getTag() throws CAPException {
        throw new CAPException("Parameter " + _PrimitiveName + ": does not support encoding");
    }

    @Override
    public int getTagClass() {
        return 0;
    }

    @Override
    public boolean getIsPrimitive() {
        return false;
    }

    @Override
    public void decodeAll(AsnInputStream ansIS) throws CAPParsingComponentException {
        throw new CAPParsingComponentException("Parameter " + _PrimitiveName + ": does not support encoding",
                CAPParsingComponentExceptionReason.MistypedParameter);
    }

    @Override
    public void decodeData(AsnInputStream ansIS, int length) throws CAPParsingComponentException {
        throw new CAPParsingComponentException("Parameter " + _PrimitiveName + ": does not support encoding",
                CAPParsingComponentExceptionReason.MistypedParameter);
    }

    @Override
    public void encodeAll(AsnOutputStream asnOs) throws CAPException {
        throw new CAPException("Parameter " + _PrimitiveName + ": does not support encoding");
    }

    @Override
    public void encodeAll(AsnOutputStream asnOs, int tagClass, int tag) throws CAPException {
        throw new CAPException("Parameter " + _PrimitiveName + ": does not support encoding");
    }

    @Override
    public void encodeData(AsnOutputStream asnOs) throws CAPException {
        throw new CAPException("Parameter " + _PrimitiveName + ": does not support encoding");
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");
        this.addInvokeIdInfo(sb);

        sb.append("]");

        return sb.toString();
    }
}
