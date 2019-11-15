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

import java.io.IOException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPMessageType;
import org.restcomm.protocols.ss7.cap.api.CAPOperationCode;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.service.gprs.EventReportGPRSRequest;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.GPRSEventSpecificInformation;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.GPRSEventType;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPID;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.GPRSEventSpecificInformationImpl;
import org.restcomm.protocols.ss7.cap.service.gprs.primitive.PDPIDImpl;
import org.restcomm.protocols.ss7.inap.api.INAPException;
import org.restcomm.protocols.ss7.inap.api.INAPParsingComponentException;
import org.restcomm.protocols.ss7.inap.api.primitives.MiscCallInfo;
import org.restcomm.protocols.ss7.inap.primitives.MiscCallInfoImpl;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class EventReportGPRSRequestImpl extends GprsMessageImpl implements EventReportGPRSRequest {

    public static final String _PrimitiveName = "EventReportGPRSRequest";

    public static final int _ID_gprsEventType = 0;
    public static final int _ID_miscGPRSInfo = 1;
    public static final int _ID_gprsEventSpecificInformation = 2;
    public static final int _ID_pdpID = 3;

    private GPRSEventType gprsEventType;
    private MiscCallInfo miscGPRSInfo;
    private GPRSEventSpecificInformation gprsEventSpecificInformation;
    private PDPID pdpID;

    public EventReportGPRSRequestImpl() {
    }

    public EventReportGPRSRequestImpl(GPRSEventType gprsEventType, MiscCallInfo miscGPRSInfo,
            GPRSEventSpecificInformation gprsEventSpecificInformation, PDPID pdpID) {
        super();
        this.gprsEventType = gprsEventType;
        this.miscGPRSInfo = miscGPRSInfo;
        this.gprsEventSpecificInformation = gprsEventSpecificInformation;
        this.pdpID = pdpID;
    }

    @Override
    public GPRSEventType getGPRSEventType() {
        return this.gprsEventType;
    }

    @Override
    public MiscCallInfo getMiscGPRSInfo() {
        return this.miscGPRSInfo;
    }

    @Override
    public GPRSEventSpecificInformation getGPRSEventSpecificInformation() {
        return this.gprsEventSpecificInformation;
    }

    @Override
    public PDPID getPDPID() {
        return this.pdpID;
    }

    @Override
    public CAPMessageType getMessageType() {
        return CAPMessageType.eventReportGPRS_Request;
    }

    @Override
    public int getOperationCode() {
        return CAPOperationCode.eventReportGPRS;
    }

    @Override
    public int getTag() throws CAPException {
        return Tag.SEQUENCE;
    }

    @Override
    public int getTagClass() {
        return Tag.CLASS_UNIVERSAL;
    }

    @Override
    public boolean getIsPrimitive() {
        return false;
    }

    @Override
    public void decodeAll(AsnInputStream ansIS) throws CAPParsingComponentException {
        try {
            int length = ansIS.readLength();
            this._decode(ansIS, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (MAPParsingComponentException e) {
            throw new CAPParsingComponentException("MAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (INAPParsingComponentException e) {
            throw new CAPParsingComponentException("INAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    @Override
    public void decodeData(AsnInputStream ansIS, int length) throws CAPParsingComponentException {
        try {
            this._decode(ansIS, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (MAPParsingComponentException e) {
            throw new CAPParsingComponentException("MAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (INAPParsingComponentException e) {
            throw new CAPParsingComponentException("INAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        }

    }

    private void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, IOException, AsnException,
            MAPParsingComponentException, INAPParsingComponentException {
        this.gprsEventType = null;
        this.miscGPRSInfo = null;
        this.gprsEventSpecificInformation = null;
        this.pdpID = null;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_gprsEventType:
                        if (!ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".gprsEventType: Parameter is not primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        int i1 = (int) ais.readInteger();
                        this.gprsEventType = GPRSEventType.getInstance(i1);
                        break;

                    case _ID_miscGPRSInfo:
                        if (ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".miscGPRSInfo: Parameter is primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.miscGPRSInfo = new MiscCallInfoImpl();
                        ((MiscCallInfoImpl) this.miscGPRSInfo).decodeAll(ais);
                        break;
                    case _ID_gprsEventSpecificInformation:
                        if (ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".gprsEventSpecificInformation: Parameter is primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.gprsEventSpecificInformation = new GPRSEventSpecificInformationImpl();
                        AsnInputStream ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        ((GPRSEventSpecificInformationImpl) this.gprsEventSpecificInformation).decodeAll(ais2);
                        break;
                    case _ID_pdpID:
                        if (!ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".pdpID: Parameter is not primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.pdpID = new PDPIDImpl();
                        ((PDPIDImpl) this.pdpID).decodeAll(ais);
                        break;
                    default:
                        ais.advanceElement();
                        break;
                }
            } else {
                ais.advanceElement();
            }
        }

    }

    @Override
    public void encodeAll(AsnOutputStream asnOs) throws CAPException {
        this.encodeAll(asnOs, this.getTagClass(), this.getTag());
    }

    @Override
    public void encodeAll(AsnOutputStream asnOs, int tagClass, int tag) throws CAPException {
        try {
            asnOs.writeTag(tagClass, this.getIsPrimitive(), tag);
            int pos = asnOs.StartContentDefiniteLength();
            this.encodeData(asnOs);
            asnOs.FinalizeContent(pos);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void encodeData(AsnOutputStream asnOs) throws CAPException {

        if (this.gprsEventType == null)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": gprsEventType must not be null");

        if (this.miscGPRSInfo == null)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": miscGPRSInfo must not be null");

        try {

            asnOs.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_gprsEventType, this.gprsEventType.getCode());

            ((MiscCallInfoImpl) this.miscGPRSInfo).encodeAll(asnOs, Tag.CLASS_CONTEXT_SPECIFIC, _ID_miscGPRSInfo);

            if (this.gprsEventSpecificInformation != null) {
                try {
                    asnOs.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_gprsEventSpecificInformation);
                    int pos = asnOs.StartContentDefiniteLength();
                    ((GPRSEventSpecificInformationImpl) this.gprsEventSpecificInformation).encodeAll(asnOs);
                    asnOs.FinalizeContent(pos);
                } catch (AsnException e) {
                    throw new CAPException("AsnException while encoding " + _PrimitiveName
                            + " parameter gprsEventSpecificInformation");
                }
            }

            if (this.pdpID != null)
                ((PDPIDImpl) this.pdpID).encodeAll(asnOs, Tag.CLASS_CONTEXT_SPECIFIC, _ID_pdpID);

        } catch (IOException e) {
            throw new CAPException("IOException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        } catch (INAPException e) {
            throw new CAPException("INAPException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName + " [");
        this.addInvokeIdInfo(sb);

        if (this.gprsEventType != null) {
            sb.append(", gprsEventType=");
            sb.append(this.gprsEventType.toString());
        }

        if (this.miscGPRSInfo != null) {
            sb.append(", miscGPRSInfo=");
            sb.append(this.miscGPRSInfo.toString());
        }

        if (this.gprsEventSpecificInformation != null) {
            sb.append(", gprsEventSpecificInformation=");
            sb.append(this.gprsEventSpecificInformation.toString());
        }

        if (this.pdpID != null) {
            sb.append("pdpID=");
            sb.append(this.pdpID.toString());
            sb.append(" ");
        }

        sb.append("]");

        return sb.toString();
    }

}
