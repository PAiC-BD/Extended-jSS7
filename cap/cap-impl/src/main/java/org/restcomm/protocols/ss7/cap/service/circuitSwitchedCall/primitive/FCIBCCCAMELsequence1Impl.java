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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.primitives.AppendFreeFormatData;
import org.restcomm.protocols.ss7.cap.api.primitives.SendingSideID;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.FCIBCCCAMELsequence1;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.FreeFormatData;
import org.restcomm.protocols.ss7.cap.primitives.CAPAsnPrimitive;
import org.restcomm.protocols.ss7.cap.primitives.SendingSideIDImpl;
import org.restcomm.protocols.ss7.inap.api.primitives.LegType;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class FCIBCCCAMELsequence1Impl implements FCIBCCCAMELsequence1, CAPAsnPrimitive {

    public static final int _ID_freeFormatData = 0;
    public static final int _ID_partyToCharge = 1;
    public static final int _ID_appendFreeFormatData = 2;

    public static final String _PrimitiveName = "FCIBCCCAMELsequence1";

    private static final String FREE_FORMAT_DATA = "freeFormatData";
    private static final String PARTY_TO_CHARGE = "partyToCharge";
    private static final String APPEND_FREE_FORMAT_DATA = "appendFreeFormatData";

    private FreeFormatData freeFormatData;
    private SendingSideID partyToCharge;
    private AppendFreeFormatData appendFreeFormatData;

    public FCIBCCCAMELsequence1Impl() {
    }

    public FCIBCCCAMELsequence1Impl(FreeFormatData freeFormatData, SendingSideID partyToCharge, AppendFreeFormatData appendFreeFormatData) {
        this.freeFormatData = freeFormatData;
        this.partyToCharge = partyToCharge;
        this.appendFreeFormatData = appendFreeFormatData;
    }

    @Override
    public FreeFormatData getFreeFormatData() {
        return freeFormatData;
    }

    @Override
    public SendingSideID getPartyToCharge() {
        return partyToCharge;
    }

    @Override
    public AppendFreeFormatData getAppendFreeFormatData() {
        return appendFreeFormatData;
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

        this.freeFormatData = null;
        this.partyToCharge = new SendingSideIDImpl(LegType.leg1);
        this.appendFreeFormatData = AppendFreeFormatData.overwrite;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_freeFormatData:
                        if (!ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".freeFormatData: Parameter is not primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.freeFormatData = new FreeFormatDataImpl();
                        ((FreeFormatDataImpl) this.freeFormatData).decodeAll(ais);
                        break;
                    case _ID_partyToCharge:
                        AsnInputStream ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.partyToCharge = new SendingSideIDImpl();
                        ((SendingSideIDImpl) this.partyToCharge).decodeAll(ais2);
                        break;
                    case _ID_appendFreeFormatData:
                        int i1 = (int) ais.readInteger();
                        this.appendFreeFormatData = AppendFreeFormatData.getInstance(i1);
                        break;

                    default:
                        ais.advanceElement();
                        break;
                }
            } else {
                ais.advanceElement();
            }
        }

        if (this.freeFormatData == null)
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                    + ": freeFormatData is mandatory but not found", CAPParsingComponentExceptionReason.MistypedParameter);
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

        if (this.freeFormatData == null)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": freeFormatData must not be null");
//        if (this.freeFormatData.length < 1 || this.freeFormatData.length > 160)
//            throw new CAPException("Error while encoding " + _PrimitiveName
//                    + ": freeFormatData length must not be from 1 to 160, found: " + this.freeFormatData.length);

        try {
            ((FreeFormatDataImpl) this.freeFormatData).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, _ID_freeFormatData);

            if (this.partyToCharge != null) {
                aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_partyToCharge);
                int pos = aos.StartContentDefiniteLength();
                ((SendingSideIDImpl) this.partyToCharge).encodeAll(aos);
                aos.FinalizeContent(pos);
            }
            if (this.appendFreeFormatData != null)
                aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_appendFreeFormatData, this.appendFreeFormatData.getCode());

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

        if (this.freeFormatData != null) {
            sb.append("freeFormatData=");
            sb.append(this.freeFormatData.toString());
            sb.append(", ");
        }
        if (this.partyToCharge != null) {
            sb.append(", partyToCharge=");
            sb.append(partyToCharge.toString());
        }
        if (this.appendFreeFormatData != null) {
            sb.append(", appendFreeFormatData=");
            sb.append(appendFreeFormatData.toString());
        }

        sb.append("]");

        return sb.toString();
    }

    private String printDataArr(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int b : arr) {
            sb.append(b);
            sb.append(", ");
        }

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<FCIBCCCAMELsequence1Impl> FCIBCC_CAMEL_SEQUENCE1_XML = new XMLFormat<FCIBCCCAMELsequence1Impl>(FCIBCCCAMELsequence1Impl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, FCIBCCCAMELsequence1Impl fciBCCCAMELsequence1)
                throws XMLStreamException {
            String vals = xml.getAttribute(APPEND_FREE_FORMAT_DATA, "");
            if (vals != null && vals.length() > 0)
                fciBCCCAMELsequence1.appendFreeFormatData = Enum.valueOf(AppendFreeFormatData.class, vals);

            fciBCCCAMELsequence1.freeFormatData = xml.get(FREE_FORMAT_DATA, FreeFormatDataImpl.class);
            fciBCCCAMELsequence1.partyToCharge = xml.get(PARTY_TO_CHARGE, SendingSideIDImpl.class);
        }

        @Override
        public void write(FCIBCCCAMELsequence1Impl fciBCCCAMELsequence1, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            if (fciBCCCAMELsequence1.appendFreeFormatData != null)
                xml.setAttribute(APPEND_FREE_FORMAT_DATA, fciBCCCAMELsequence1.appendFreeFormatData.toString());

            xml.add((FreeFormatDataImpl) fciBCCCAMELsequence1.freeFormatData, FREE_FORMAT_DATA, FreeFormatDataImpl.class);
            xml.add((SendingSideIDImpl) fciBCCCAMELsequence1.partyToCharge, PARTY_TO_CHARGE, SendingSideIDImpl.class);
        }
    };
}
