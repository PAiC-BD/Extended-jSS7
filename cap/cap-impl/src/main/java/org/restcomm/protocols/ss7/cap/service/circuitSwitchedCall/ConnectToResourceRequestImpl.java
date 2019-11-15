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
import org.restcomm.protocols.ss7.cap.api.isup.CalledPartyNumberCap;
import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.ConnectToResourceRequest;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.ServiceInteractionIndicatorsTwo;
import org.restcomm.protocols.ss7.cap.isup.CalledPartyNumberCapImpl;
import org.restcomm.protocols.ss7.cap.primitives.CAPExtensionsImpl;
import org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive.ServiceInteractionIndicatorsTwoImpl;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class ConnectToResourceRequestImpl extends CircuitSwitchedCallMessageImpl implements ConnectToResourceRequest {

    public static final int _ID_resourceAddress_ipRoutingAddress = 0;
    public static final int _ID_resourceAddress_none = 3;
    public static final int _ID_extensions = 4;
    public static final int _ID_serviceInteractionIndicatorsTwo = 7;
    public static final int _ID_callSegmentID = 50;

    public static final String _PrimitiveName = "ConnectToResourceIndication";

    private static final String RESOURCE_ADDRESS_IP_ROUTING_ADDRESS = "resourceAddress_IPRoutingAddress";
    private static final String RESOURCE_ADDRESS_NULL = "resourceAddress_Null";
    private static final String EXTENSIONS = "extensions";
    private static final String SERVICE_INTERACTION_INDICATORS_TWO = "serviceInteractionIndicatorsTwo";
    private static final String CALL_SEGMENT_ID = "callSegmentID";

    private CalledPartyNumberCap resourceAddress_IPRoutingAddress;
    private boolean resourceAddress_Null;
    private CAPExtensions extensions;
    private ServiceInteractionIndicatorsTwo serviceInteractionIndicatorsTwo;
    private Integer callSegmentID;

    public ConnectToResourceRequestImpl() {
    }

    public ConnectToResourceRequestImpl(CalledPartyNumberCap resourceAddress_IPRoutingAddress, boolean resourceAddress_Null,
            CAPExtensions extensions, ServiceInteractionIndicatorsTwo serviceInteractionIndicatorsTwo, Integer callSegmentID) {
        this.resourceAddress_IPRoutingAddress = resourceAddress_IPRoutingAddress;
        this.resourceAddress_Null = resourceAddress_Null;
        this.extensions = extensions;
        this.serviceInteractionIndicatorsTwo = serviceInteractionIndicatorsTwo;
        this.callSegmentID = callSegmentID;
    }

    @Override
    public CAPMessageType getMessageType() {
        return CAPMessageType.connectToResource_Request;
    }

    @Override
    public int getOperationCode() {
        return CAPOperationCode.connectToResource;
    }

    @Override
    public CalledPartyNumberCap getResourceAddress_IPRoutingAddress() {
        return resourceAddress_IPRoutingAddress;
    }

    @Override
    public boolean getResourceAddress_Null() {
        return resourceAddress_Null;
    }

    @Override
    public CAPExtensions getExtensions() {
        return extensions;
    }

    @Override
    public ServiceInteractionIndicatorsTwo getServiceInteractionIndicatorsTwo() {
        return serviceInteractionIndicatorsTwo;
    }

    @Override
    public Integer getCallSegmentID() {
        return callSegmentID;
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

        this.resourceAddress_IPRoutingAddress = null;
        this.resourceAddress_Null = false;
        this.extensions = null;
        this.serviceInteractionIndicatorsTwo = null;
        this.callSegmentID = null;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {

                    case _ID_resourceAddress_ipRoutingAddress:
                        this.resourceAddress_IPRoutingAddress = new CalledPartyNumberCapImpl();
                        ((CalledPartyNumberCapImpl) this.resourceAddress_IPRoutingAddress).decodeAll(ais);
                        break;
                    case _ID_resourceAddress_none:
                        ais.readNull();
                        this.resourceAddress_Null = true;
                        break;
                    case _ID_extensions:
                        this.extensions = new CAPExtensionsImpl();
                        ((CAPExtensionsImpl) this.extensions).decodeAll(ais);
                        break;
                    case _ID_serviceInteractionIndicatorsTwo:
                        this.serviceInteractionIndicatorsTwo = new ServiceInteractionIndicatorsTwoImpl();
                        ((ServiceInteractionIndicatorsTwoImpl) this.serviceInteractionIndicatorsTwo).decodeAll(ais);
                        break;
                    case _ID_callSegmentID:
                        this.callSegmentID = (int) ais.readInteger();
                        break;

                    default:
                        ais.advanceElement();
                        break;
                }
            } else {
                ais.advanceElement();
            }
        }

        int choiceCnt = 0;
        if (this.resourceAddress_IPRoutingAddress != null)
            choiceCnt++;
        if (this.resourceAddress_Null)
            choiceCnt++;
        if (choiceCnt != 1)
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                    + ": resourceAddress parameter must have 1 choice, found: " + choiceCnt,
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

        int choiceCnt = 0;
        if (this.resourceAddress_IPRoutingAddress != null)
            choiceCnt++;
        if (this.resourceAddress_Null)
            choiceCnt++;
        if (choiceCnt != 1)
            throw new CAPException("Error while encoding " + _PrimitiveName
                    + ": resourceAddress parameter must have 1 choice, found: " + choiceCnt);

        try {

            if (this.resourceAddress_IPRoutingAddress != null)
                ((CalledPartyNumberCapImpl) this.resourceAddress_IPRoutingAddress).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC,
                        _ID_resourceAddress_ipRoutingAddress);
            if (this.resourceAddress_Null)
                aos.writeNull(Tag.CLASS_CONTEXT_SPECIFIC, _ID_resourceAddress_none);
            if (this.extensions != null)
                ((CAPExtensionsImpl) this.extensions).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, _ID_extensions);
            if (this.serviceInteractionIndicatorsTwo != null)
                ((ServiceInteractionIndicatorsTwoImpl) this.serviceInteractionIndicatorsTwo).encodeAll(aos,
                        Tag.CLASS_CONTEXT_SPECIFIC, _ID_serviceInteractionIndicatorsTwo);
            if (this.callSegmentID != null)
                aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_callSegmentID, this.callSegmentID);

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

        if (this.resourceAddress_IPRoutingAddress != null) {
            sb.append(", resourceAddress: IPRoutingAddress=");
            sb.append(resourceAddress_IPRoutingAddress.toString());
        }
        if (this.resourceAddress_Null) {
            sb.append(", resourceAddress: Null");
        }
        if (this.extensions != null) {
            sb.append(", extensions=");
            sb.append(extensions.toString());
        }
        if (this.serviceInteractionIndicatorsTwo != null) {
            sb.append(", serviceInteractionIndicatorsTwo=");
            sb.append(serviceInteractionIndicatorsTwo.toString());
        }
        if (this.callSegmentID != null) {
            sb.append(", callSegmentID=");
            sb.append(callSegmentID.toString());
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<ConnectToResourceRequestImpl> CONNECT_TO_RESOURCE_REQUEST_XML = new XMLFormat<ConnectToResourceRequestImpl>(
            ConnectToResourceRequestImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, ConnectToResourceRequestImpl connectToResourceRequest)
                throws XMLStreamException {
            CIRCUIT_SWITCHED_CALL_MESSAGE_XML.read(xml, connectToResourceRequest);

            int vali = xml.getAttribute(CALL_SEGMENT_ID, -1);
            if (vali != -1)
                connectToResourceRequest.callSegmentID = vali;

            connectToResourceRequest.resourceAddress_IPRoutingAddress = xml.get(RESOURCE_ADDRESS_IP_ROUTING_ADDRESS,
                    CalledPartyNumberCapImpl.class);
            Boolean valb = xml.get(RESOURCE_ADDRESS_NULL, Boolean.class);
            if (valb != null)
                connectToResourceRequest.resourceAddress_Null = valb;
            else
                connectToResourceRequest.resourceAddress_Null = false;

            int choiceCount = 0;
            if (connectToResourceRequest.resourceAddress_IPRoutingAddress != null)
                choiceCount++;
            if (connectToResourceRequest.resourceAddress_Null)
                choiceCount++;

            if (choiceCount != 1)
                throw new XMLStreamException(
                        "ConnectToResourceRequest decoding error: there must be one choice selected, found: " + choiceCount);

            connectToResourceRequest.extensions = xml.get(EXTENSIONS, CAPExtensionsImpl.class);
            connectToResourceRequest.serviceInteractionIndicatorsTwo = xml.get(SERVICE_INTERACTION_INDICATORS_TWO,
                    ServiceInteractionIndicatorsTwoImpl.class);
        }

        @Override
        public void write(ConnectToResourceRequestImpl connectToResourceRequest, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            CIRCUIT_SWITCHED_CALL_MESSAGE_XML.write(connectToResourceRequest, xml);

            if (connectToResourceRequest.callSegmentID != null)
                xml.setAttribute(CALL_SEGMENT_ID, connectToResourceRequest.callSegmentID);

            if (connectToResourceRequest.resourceAddress_IPRoutingAddress != null)
                xml.add((CalledPartyNumberCapImpl) connectToResourceRequest.resourceAddress_IPRoutingAddress,
                        RESOURCE_ADDRESS_IP_ROUTING_ADDRESS, CalledPartyNumberCapImpl.class);
            if (connectToResourceRequest.resourceAddress_Null)
                xml.add(connectToResourceRequest.resourceAddress_Null, RESOURCE_ADDRESS_NULL, Boolean.class);

            if (connectToResourceRequest.getExtensions() != null)
                xml.add((CAPExtensionsImpl) connectToResourceRequest.getExtensions(), EXTENSIONS, CAPExtensionsImpl.class);
            if (connectToResourceRequest.serviceInteractionIndicatorsTwo != null)
                xml.add((ServiceInteractionIndicatorsTwoImpl) connectToResourceRequest.serviceInteractionIndicatorsTwo,
                        SERVICE_INTERACTION_INDICATORS_TWO, ServiceInteractionIndicatorsTwoImpl.class);
        }
    };
}
