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
import org.restcomm.protocols.ss7.cap.api.primitives.AChChargingAddress;
import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.primitives.ReceivingSideID;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.TimeDurationChargingResult;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.TimeInformation;
import org.restcomm.protocols.ss7.cap.primitives.AChChargingAddressImpl;
import org.restcomm.protocols.ss7.cap.primitives.CAPExtensionsImpl;
import org.restcomm.protocols.ss7.cap.primitives.ReceivingSideIDImpl;
import org.restcomm.protocols.ss7.cap.primitives.SequenceBase;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 * @author sergey vetyutnev
 * @author Amit Bhayani
 *
 */
public class TimeDurationChargingResultImpl extends SequenceBase implements TimeDurationChargingResult {

    private static final String PARTY_TO_CHARGE = "partyToCharge";
    private static final String TIME_INFORMATION = "timeInformation";
    private static final String LEG_ACTIVE = "legActive";
    private static final String CALL_LEG_RELEASED_AT_TCP_EXPIRY = "callLegReleasedAtTcpExpiry";
    private static final String EXTENSIONS = "extensions";
    private static final String A_CH_CHARGING_ADDRESS = "aChChargingAddress";

    public static final int _ID_partyToCharge = 0;
    public static final int _ID_timeInformation = 1;
    public static final int _ID_legActive = 2;
    public static final int _ID_callLegReleasedAtTcpExpiry = 3;
    public static final int _ID_extensions = 4;
    public static final int _ID_aChChargingAddress = 5;

    private ReceivingSideID partyToCharge;
    private TimeInformation timeInformation;
    private boolean legActive;
    private boolean callLegReleasedAtTcpExpiry;
    private CAPExtensions extensions;
    private AChChargingAddress aChChargingAddress;

    public TimeDurationChargingResultImpl() {
        super("TimeDurationChargingResult");
    }

    public TimeDurationChargingResultImpl(ReceivingSideID partyToCharge, TimeInformation timeInformation, boolean legActive,
            boolean callLegReleasedAtTcpExpiry, CAPExtensions extensions, AChChargingAddress aChChargingAddress) {
        super("TimeDurationChargingResult");
        this.partyToCharge = partyToCharge;
        this.timeInformation = timeInformation;
        this.legActive = legActive;
        this.callLegReleasedAtTcpExpiry = callLegReleasedAtTcpExpiry;
        this.extensions = extensions;
        this.aChChargingAddress = aChChargingAddress;
    }

    @Override
    public ReceivingSideID getPartyToCharge() {
        return partyToCharge;
    }

    @Override
    public TimeInformation getTimeInformation() {
        return timeInformation;
    }

    @Override
    public boolean getLegActive() {
        return legActive;
    }

    @Override
    public boolean getCallLegReleasedAtTcpExpiry() {
        return callLegReleasedAtTcpExpiry;
    }

    @Override
    public CAPExtensions getExtensions() {
        return extensions;
    }

    @Override
    public AChChargingAddress getAChChargingAddress() {
        return aChChargingAddress;
    }

    protected void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, MAPParsingComponentException,
            IOException, AsnException {

        this.partyToCharge = null;
        this.timeInformation = null;
        this.legActive = true;
        this.callLegReleasedAtTcpExpiry = false;
        this.extensions = null;
        this.aChChargingAddress = null; // TODO: DEFAULT
                                        // legID:receivingSideID:leg1

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_partyToCharge:
                        AsnInputStream ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.partyToCharge = new ReceivingSideIDImpl();
                        ((ReceivingSideIDImpl) this.partyToCharge).decodeAll(ais2);
                        break;
                    case _ID_timeInformation:
                        ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.timeInformation = new TimeInformationImpl();
                        ((TimeInformationImpl) this.timeInformation).decodeAll(ais2);
                        break;
                    case _ID_legActive:
                        this.legActive = ais.readBoolean();
                        break;
                    case _ID_callLegReleasedAtTcpExpiry:
                        ais.readNull();
                        this.callLegReleasedAtTcpExpiry = true;
                        break;
                    case _ID_extensions:
                        this.extensions = new CAPExtensionsImpl();
                        ((CAPExtensionsImpl) this.extensions).decodeAll(ais);
                        break;
                    case _ID_aChChargingAddress:
                        ais2 = ais.readSequenceStream();
                        ais2.readTag();
                        this.aChChargingAddress = new AChChargingAddressImpl();
                        ((AChChargingAddressImpl) this.aChChargingAddress).decodeAll(ais2);
                        break;

                    default:
                        ais.advanceElement();
                        break;
                }
            } else {
                ais.advanceElement();
            }
        }

        if (this.partyToCharge == null || this.timeInformation == null)
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                    + ": partyToCharge and timeInformation are mandatory but not found",
                    CAPParsingComponentExceptionReason.MistypedParameter);
    }

    @Override
    public void encodeData(AsnOutputStream aos) throws CAPException {

        if (this.partyToCharge == null || this.timeInformation == null)
            throw new CAPException("Error while encoding " + _PrimitiveName
                    + ": partyToCharge and timeInformation must not be null");

        try {
            aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_partyToCharge);
            int pos = aos.StartContentDefiniteLength();
            ((ReceivingSideIDImpl) this.partyToCharge).encodeAll(aos);
            aos.FinalizeContent(pos);

            aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_timeInformation);
            pos = aos.StartContentDefiniteLength();
            ((TimeInformationImpl) this.timeInformation).encodeAll(aos);
            aos.FinalizeContent(pos);

            if (this.legActive == false)
                aos.writeBoolean(Tag.CLASS_CONTEXT_SPECIFIC, _ID_legActive, this.legActive);

            if (this.callLegReleasedAtTcpExpiry)
                aos.writeNull(Tag.CLASS_CONTEXT_SPECIFIC, _ID_callLegReleasedAtTcpExpiry);

            if (this.extensions != null)
                ((CAPExtensionsImpl) this.extensions).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, _ID_extensions);

            if (this.aChChargingAddress != null) {
                aos.writeTag(Tag.CLASS_CONTEXT_SPECIFIC, false, _ID_aChChargingAddress);
                pos = aos.StartContentDefiniteLength();
                ((AChChargingAddressImpl) this.aChChargingAddress).encodeAll(aos);
                aos.FinalizeContent(pos);
            }
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

        if (this.partyToCharge != null) {
            sb.append("partyToCharge=");
            sb.append(partyToCharge.toString());
        }
        if (this.timeInformation != null) {
            sb.append(", timeInformation=");
            sb.append(timeInformation.toString());
        }
        if (this.legActive) {
            sb.append(", legActive");
        }
        if (this.callLegReleasedAtTcpExpiry) {
            sb.append(", callLegReleasedAtTcpExpiry");
        }
        if (this.extensions != null) {
            sb.append(", extensions=");
            sb.append(extensions.toString());
        }
        if (this.aChChargingAddress != null) {
            sb.append(", aChChargingAddress=");
            sb.append(aChChargingAddress.toString());
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<TimeDurationChargingResultImpl> TIME_DURATION_CHARGING_RESULT_XML = new XMLFormat<TimeDurationChargingResultImpl>(
            TimeDurationChargingResultImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, TimeDurationChargingResultImpl timeDurationChargingResult)
                throws XMLStreamException {
            timeDurationChargingResult.partyToCharge = xml.get(PARTY_TO_CHARGE, ReceivingSideIDImpl.class);
            timeDurationChargingResult.timeInformation = xml.get(TIME_INFORMATION, TimeInformationImpl.class);

            Boolean bval = xml.get(LEG_ACTIVE, Boolean.class);
            if (bval != null)
                timeDurationChargingResult.legActive = bval;
            bval = xml.get(CALL_LEG_RELEASED_AT_TCP_EXPIRY, Boolean.class);
            if (bval != null)
                timeDurationChargingResult.callLegReleasedAtTcpExpiry = bval;

            timeDurationChargingResult.aChChargingAddress = xml.get(A_CH_CHARGING_ADDRESS, AChChargingAddressImpl.class);

            timeDurationChargingResult.extensions = xml.get(EXTENSIONS, CAPExtensionsImpl.class);

        }

        @Override
        public void write(TimeDurationChargingResultImpl timeDurationChargingResult, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {

            if (timeDurationChargingResult.partyToCharge != null)
                xml.add((ReceivingSideIDImpl) timeDurationChargingResult.partyToCharge, PARTY_TO_CHARGE,
                        ReceivingSideIDImpl.class);

            if (timeDurationChargingResult.timeInformation != null)
                xml.add((TimeInformationImpl) timeDurationChargingResult.timeInformation, TIME_INFORMATION,
                        TimeInformationImpl.class);

            if (timeDurationChargingResult.legActive)
                xml.add(timeDurationChargingResult.legActive, LEG_ACTIVE, Boolean.class);
            if (timeDurationChargingResult.callLegReleasedAtTcpExpiry)
                xml.add(timeDurationChargingResult.callLegReleasedAtTcpExpiry, CALL_LEG_RELEASED_AT_TCP_EXPIRY, Boolean.class);

            if (timeDurationChargingResult.aChChargingAddress != null)
                xml.add((AChChargingAddressImpl) timeDurationChargingResult.aChChargingAddress, A_CH_CHARGING_ADDRESS, AChChargingAddressImpl.class);

            if (timeDurationChargingResult.extensions != null)
                xml.add((CAPExtensionsImpl) timeDurationChargingResult.extensions, EXTENSIONS, CAPExtensionsImpl.class);

        }
    };
}
