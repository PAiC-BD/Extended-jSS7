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
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.DpSpecificCriteria;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.DpSpecificCriteriaAlt;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.MidCallControlInfo;
import org.restcomm.protocols.ss7.cap.primitives.CAPAsnPrimitive;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 *
 * @author sergey vetyutnev
 *
 */
public class DpSpecificCriteriaImpl implements DpSpecificCriteria, CAPAsnPrimitive {

    public static final int _ID_applicationTimer = 1;
    public static final int _ID_midCallControlInfo = 2;
    public static final int _ID_dpSpecificCriteriaAlt = 3;

    public static final String _PrimitiveName = "DpSpecificCriteria";

    private static final String APPLICATION_TIMER = "applicationTimer";
    private static final String MID_CALL_CONTROL_INFO = "midCallControlInfo";
    private static final String DP_SPECIFIC_CRITERIA_ALT = "dpSpecificCriteriaAlt";

    private Integer applicationTimer;
    private MidCallControlInfo midCallControlInfo;
    private DpSpecificCriteriaAlt dpSpecificCriteriaAlt;

    public DpSpecificCriteriaImpl() {
    }

    public DpSpecificCriteriaImpl(Integer applicationTimer) {
        this.applicationTimer = applicationTimer;
    }

    public DpSpecificCriteriaImpl(MidCallControlInfo midCallControlInfo) {
        this.midCallControlInfo = midCallControlInfo;
    }

    public DpSpecificCriteriaImpl(DpSpecificCriteriaAlt dpSpecificCriteriaAlt) {
        this.dpSpecificCriteriaAlt = dpSpecificCriteriaAlt;
    }

    @Override
    public Integer getApplicationTimer() {
        return applicationTimer;
    }

    @Override
    public MidCallControlInfo getMidCallControlInfo() {
        return midCallControlInfo;
    }

    @Override
    public DpSpecificCriteriaAlt getDpSpecificCriteriaAlt() {
        return dpSpecificCriteriaAlt;
    }

    @Override
    public int getTag() throws CAPException {
        if (this.applicationTimer != null) {
            return _ID_applicationTimer;
        }
        if (this.midCallControlInfo != null) {
            return _ID_midCallControlInfo;
        }
        if (this.dpSpecificCriteriaAlt != null) {
            return _ID_dpSpecificCriteriaAlt;
        }

        throw new CAPException("Error while defining a " + _PrimitiveName + ": none of choices is defined");
    }

    @Override
    public int getTagClass() {
        return Tag.CLASS_CONTEXT_SPECIFIC;
    }

    @Override
    public boolean getIsPrimitive() {
        if (this.applicationTimer != null)
            return true;
        else
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
        }
    }

    private void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, MAPParsingComponentException,
            IOException, AsnException {

        this.applicationTimer = null;
        this.midCallControlInfo = null;
        this.dpSpecificCriteriaAlt = null;

        if (ansIS.getTagClass() != Tag.CLASS_CONTEXT_SPECIFIC)
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": bad tagClass",
                    CAPParsingComponentExceptionReason.MistypedParameter);

        switch (ansIS.getTag()) {
        case _ID_applicationTimer:
            if (!ansIS.isTagPrimitive())
                throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": choice applicationTimer is not primitive",
                        CAPParsingComponentExceptionReason.MistypedParameter);
            this.applicationTimer = (int) ansIS.readIntegerData(length);
            if (this.applicationTimer < 0 || this.applicationTimer > 2047)
                throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                        + ": bad applicationTimer parameter value: must be from 0 to 2047, found " + this.applicationTimer,
                        CAPParsingComponentExceptionReason.MistypedParameter);
            break;
        case _ID_midCallControlInfo:
            this.midCallControlInfo = new MidCallControlInfoImpl();
            ((MidCallControlInfoImpl) this.midCallControlInfo).decodeData(ansIS, length);
            break;
        case _ID_dpSpecificCriteriaAlt:
            this.dpSpecificCriteriaAlt = new DpSpecificCriteriaAltImpl();
            ((DpSpecificCriteriaAltImpl) this.dpSpecificCriteriaAlt).decodeData(ansIS, length);
            break;
        default:
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": bad tag", CAPParsingComponentExceptionReason.MistypedParameter);
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

        int choiceCnt = 0;
        if (this.applicationTimer != null)
            choiceCnt++;
        if (this.midCallControlInfo != null)
            choiceCnt++;
        if (dpSpecificCriteriaAlt != null)
            choiceCnt++;
        if (choiceCnt != 1)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": only one choice is possible, found: "
                    + choiceCnt);

        if (this.applicationTimer != null) {
            try {
                asnOs.writeIntegerData(this.applicationTimer);
            } catch (IOException e) {
                throw new CAPException("IOException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
            }
        } else if (this.midCallControlInfo != null) {
            ((MidCallControlInfoImpl) midCallControlInfo).encodeData(asnOs);
        } else if (this.dpSpecificCriteriaAlt != null) {
            ((DpSpecificCriteriaAltImpl) dpSpecificCriteriaAlt).encodeData(asnOs);
        }
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");
        if (this.applicationTimer != null) {
            sb.append("applicationTimer=");
            sb.append(applicationTimer);
        }
        if (this.midCallControlInfo != null) {
            sb.append("midCallControlInfo=");
            sb.append(midCallControlInfo);
        }
        if (this.dpSpecificCriteriaAlt != null) {
            sb.append("dpSpecificCriteriaAlt=");
            sb.append(dpSpecificCriteriaAlt);
        }
        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<DpSpecificCriteriaImpl> DP_SPECIFIC_CRITERIA_XML = new XMLFormat<DpSpecificCriteriaImpl>(
            DpSpecificCriteriaImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, DpSpecificCriteriaImpl dpSpecificCriteria)
                throws XMLStreamException {
            dpSpecificCriteria.applicationTimer = xml.get(APPLICATION_TIMER, Integer.class);

            dpSpecificCriteria.midCallControlInfo = xml.get(MID_CALL_CONTROL_INFO, MidCallControlInfoImpl.class);
            dpSpecificCriteria.dpSpecificCriteriaAlt = xml.get(DP_SPECIFIC_CRITERIA_ALT, DpSpecificCriteriaAltImpl.class);
        }

        @Override
        public void write(DpSpecificCriteriaImpl dpSpecificCriteria, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            if (dpSpecificCriteria.getApplicationTimer() != null)
                xml.add((Integer) dpSpecificCriteria.getApplicationTimer(), APPLICATION_TIMER, Integer.class);

            if (dpSpecificCriteria.getMidCallControlInfo() != null)
                xml.add((MidCallControlInfoImpl) dpSpecificCriteria.getMidCallControlInfo(), MID_CALL_CONTROL_INFO, MidCallControlInfoImpl.class);
            if (dpSpecificCriteria.getDpSpecificCriteriaAlt() != null)
                xml.add((DpSpecificCriteriaAltImpl) dpSpecificCriteria.getDpSpecificCriteriaAlt(), DP_SPECIFIC_CRITERIA_ALT, DpSpecificCriteriaAltImpl.class);
        }
    };
}
