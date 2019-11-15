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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPMessageType;
import org.restcomm.protocols.ss7.cap.api.CAPOperationCode;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.PromptAndCollectUserInformationRequest;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.CollectedInfo;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.InformationToSend;
import org.restcomm.protocols.ss7.cap.primitives.CAPExtensionsImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.CollectedInfoImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.InformationToSendImpl;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class PromptAndCollectUserInformationRequestImpl extends CircuitSwitchedCallMessageImpl implements
        PromptAndCollectUserInformationRequest {

    public static final int _ID_collectedInfo = 0;
    public static final int _ID_disconnectFromIPForbidden = 1;
    public static final int _ID_informationToSend = 2;
    public static final int _ID_extensions = 3;
    public static final int _ID_callSegmentID = 4;
    public static final int _ID_requestAnnouncementStartedNotification = 51;

    public static final String _PrimitiveName = "PromptAndCollectUserInformationRequestIndication";

    private static final String COLLECTED_INFO = "collectedInfo";
    private static final String DISCONNECT_FROM_IP_FORBIDDEN = "disconnectFromIPForbidden";
    private static final String INFORMATION_TO_SEND = "informationToSend";
    private static final String EXTENSIONS = "extensions";
    private static final String CALL_SEGMENT_ID = "callSegmentID";
    private static final String REQUEST_ANNOUNCEMENT_STARTED_NOTIFICATION = "requestAnnouncementStartedNotification";

    private CollectedInfo collectedInfo;
    private Boolean disconnectFromIPForbidden;
    private InformationToSend informationToSend;
    private CAPExtensions extensions;
    private Integer callSegmentID;
    private Boolean requestAnnouncementStartedNotification;

    public PromptAndCollectUserInformationRequestImpl() {
    }

    public PromptAndCollectUserInformationRequestImpl(CollectedInfo collectedInfo, Boolean disconnectFromIPForbidden,
            InformationToSend informationToSend, CAPExtensions extensions, Integer callSegmentID,
            Boolean requestAnnouncementStartedNotification) {
        this.collectedInfo = collectedInfo;
        this.disconnectFromIPForbidden = disconnectFromIPForbidden;
        this.informationToSend = informationToSend;
        this.extensions = extensions;
        this.callSegmentID = callSegmentID;
        this.requestAnnouncementStartedNotification = requestAnnouncementStartedNotification;
    }

    @Override
    public CAPMessageType getMessageType() {
        return CAPMessageType.promptAndCollectUserInformation_Request;
    }

    @Override
    public int getOperationCode() {
        return CAPOperationCode.promptAndCollectUserInformation;
    }

    @Override
    public CollectedInfo getCollectedInfo() {
        return collectedInfo;
    }

    @Override
    public Boolean getDisconnectFromIPForbidden() {
        return disconnectFromIPForbidden;
    }

    @Override
    public InformationToSend getInformationToSend() {
        return informationToSend;
    }

    @Override
    public CAPExtensions getExtensions() {
        return extensions;
    }

    @Override
    public Integer getCallSegmentID() {
        return callSegmentID;
    }

    @Override
    public Boolean getRequestAnnouncementStartedNotification() {
        return requestAnnouncementStartedNotification;
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
        }
    }

    private void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, IOException, AsnException {

        this.collectedInfo = null;
        this.disconnectFromIPForbidden = null;
        this.informationToSend = null;
        this.extensions = null;
        this.callSegmentID = null;
        this.requestAnnouncementStartedNotification = null;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_collectedInfo:
                        AsnInputStream ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.collectedInfo = new CollectedInfoImpl();
                        ((CollectedInfoImpl) this.collectedInfo).decodeAll(ais2);
                        break;
                    case _ID_disconnectFromIPForbidden:
                        this.disconnectFromIPForbidden = ais.readBoolean();
                        break;
                    case _ID_informationToSend:
                        ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.informationToSend = new InformationToSendImpl();
                        ((InformationToSendImpl) this.informationToSend).decodeAll(ais2);
                        break;
                    case _ID_extensions:
                        this.extensions = new CAPExtensionsImpl();
                        ((CAPExtensionsImpl) this.extensions).decodeAll(ais);
                        break;
                    case _ID_callSegmentID:
                        this.callSegmentID = (int) ais.readInteger();
                        break;
                    case _ID_requestAnnouncementStartedNotification:
                        this.requestAnnouncementStartedNotification = ais.readBoolean();
                        break;

                    default:
                        ais.advanceElement();
                        break;
                }
            } else {
                ais.advanceElement();
            }
        }

        if (this.collectedInfo == null)
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                    + ": parameter collectedInfo is mandatory but not found",
                    CAPParsingComponentExceptionReason.MistypedParameter);
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
    public void encodeData(AsnOutputStream aos) throws CAPException {

        if (this.collectedInfo == null)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": collectedInfo must not be null");

        try {

            aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_collectedInfo);
            int pos = aos.StartContentDefiniteLength();
            ((CollectedInfoImpl) this.collectedInfo).encodeAll(aos);
            aos.FinalizeContent(pos);

            if (this.disconnectFromIPForbidden != null)
                aos.writeBoolean(Tag.CLASS_CONTEXT_SPECIFIC, _ID_disconnectFromIPForbidden, this.disconnectFromIPForbidden);

            if (this.informationToSend != null) {
                aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_informationToSend);
                pos = aos.StartContentDefiniteLength();
                ((InformationToSendImpl) this.informationToSend).encodeAll(aos);
                aos.FinalizeContent(pos);
            }

            if (this.extensions != null)
                ((CAPExtensionsImpl) this.extensions).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, _ID_extensions);

            if (this.callSegmentID != null)
                aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_callSegmentID, this.callSegmentID);
            if (this.requestAnnouncementStartedNotification != null)
                aos.writeBoolean(Tag.CLASS_CONTEXT_SPECIFIC, _ID_requestAnnouncementStartedNotification,
                        this.requestAnnouncementStartedNotification);

        } catch (IOException e) {
            throw new CAPException("IOException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");
        this.addInvokeIdInfo(sb);

        if (this.collectedInfo != null) {
            sb.append(", collectedInfo=");
            sb.append(collectedInfo.toString());
        }
        if (this.disconnectFromIPForbidden != null) {
            sb.append(", disconnectFromIPForbidden=");
            sb.append(disconnectFromIPForbidden);
        }
        if (this.informationToSend != null) {
            sb.append(", informationToSend=");
            sb.append(informationToSend.toString());
        }
        if (this.extensions != null) {
            sb.append(", extensions=");
            sb.append(extensions.toString());
        }
        if (this.callSegmentID != null) {
            sb.append(", callSegmentID=");
            sb.append(callSegmentID);
        }
        if (this.requestAnnouncementStartedNotification != null) {
            sb.append(", requestAnnouncementStartedNotification=");
            sb.append(requestAnnouncementStartedNotification);
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<PromptAndCollectUserInformationRequestImpl> PROMPT_AND_COLLECT_USER_INFORMATION_REQUEST_XML = new XMLFormat<PromptAndCollectUserInformationRequestImpl>(
            PromptAndCollectUserInformationRequestImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml,
                PromptAndCollectUserInformationRequestImpl promptAndCollectUserInformationRequest) throws XMLStreamException {
            CIRCUIT_SWITCHED_CALL_MESSAGE_XML.read(xml, promptAndCollectUserInformationRequest);

            String vals = xml.getAttribute(DISCONNECT_FROM_IP_FORBIDDEN, "");
            if (vals != null && vals.length() > 0)
                promptAndCollectUserInformationRequest.disconnectFromIPForbidden = Boolean.valueOf(vals);
            int vali = xml.getAttribute(CALL_SEGMENT_ID, -1);
            if (vali != -1)
                promptAndCollectUserInformationRequest.callSegmentID = vali;
            vals = xml.getAttribute(REQUEST_ANNOUNCEMENT_STARTED_NOTIFICATION, "");
            if (vals != null && vals.length() > 0)
                promptAndCollectUserInformationRequest.requestAnnouncementStartedNotification = Boolean.valueOf(vals);

            promptAndCollectUserInformationRequest.collectedInfo = xml.get(COLLECTED_INFO, CollectedInfoImpl.class);
            promptAndCollectUserInformationRequest.informationToSend = xml
                    .get(INFORMATION_TO_SEND, InformationToSendImpl.class);
            promptAndCollectUserInformationRequest.extensions = xml.get(EXTENSIONS, CAPExtensionsImpl.class);
        }

        @Override
        public void write(PromptAndCollectUserInformationRequestImpl promptAndCollectUserInformationRequest,
                javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {
            CIRCUIT_SWITCHED_CALL_MESSAGE_XML.write(promptAndCollectUserInformationRequest, xml);

            if (promptAndCollectUserInformationRequest.disconnectFromIPForbidden != null)
                xml.setAttribute(DISCONNECT_FROM_IP_FORBIDDEN, promptAndCollectUserInformationRequest.disconnectFromIPForbidden);
            if (promptAndCollectUserInformationRequest.callSegmentID != null)
                xml.setAttribute(CALL_SEGMENT_ID, promptAndCollectUserInformationRequest.callSegmentID);
            if (promptAndCollectUserInformationRequest.requestAnnouncementStartedNotification != null)
                xml.setAttribute(REQUEST_ANNOUNCEMENT_STARTED_NOTIFICATION,
                        promptAndCollectUserInformationRequest.requestAnnouncementStartedNotification);

            if (promptAndCollectUserInformationRequest.collectedInfo != null)
                xml.add((CollectedInfoImpl) promptAndCollectUserInformationRequest.collectedInfo, COLLECTED_INFO,
                        CollectedInfoImpl.class);
            if (promptAndCollectUserInformationRequest.informationToSend != null)
                xml.add((InformationToSendImpl) promptAndCollectUserInformationRequest.informationToSend, INFORMATION_TO_SEND,
                        InformationToSendImpl.class);
            if (promptAndCollectUserInformationRequest.getExtensions() != null)
                xml.add((CAPExtensionsImpl) promptAndCollectUserInformationRequest.getExtensions(), EXTENSIONS,
                        CAPExtensionsImpl.class);
        }
    };
}
