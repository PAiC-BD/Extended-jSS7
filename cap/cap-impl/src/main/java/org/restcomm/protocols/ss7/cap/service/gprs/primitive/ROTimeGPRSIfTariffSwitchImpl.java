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
package org.restcomm.protocols.ss7.cap.service.gprs.primitive;

import java.io.IOException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.ROTimeGPRSIfTariffSwitch;
import org.restcomm.protocols.ss7.cap.primitives.SequenceBase;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class ROTimeGPRSIfTariffSwitchImpl extends SequenceBase implements ROTimeGPRSIfTariffSwitch {

    public static final int _ID_roTimeGPRSSinceLastTariffSwitch = 0;
    public static final int _ID_roTimeGPRSTariffSwitchInterval = 1;

    public static final int _ID_ROTimeGPRSIfTariffSwitch = 1;

    public Integer roTimeGPRSSinceLastTariffSwitch;
    public Integer roTimeGPRSTariffSwitchInterval;

    public ROTimeGPRSIfTariffSwitchImpl() {
        super("ROTimeGPRSIfTariffSwitch");
    }

    public ROTimeGPRSIfTariffSwitchImpl(Integer roTimeGPRSSinceLastTariffSwitch, Integer roTimeGPRSTariffSwitchInterval) {
        super("ROTimeGPRSIfTariffSwitch");
        this.roTimeGPRSSinceLastTariffSwitch = roTimeGPRSSinceLastTariffSwitch;
        this.roTimeGPRSTariffSwitchInterval = roTimeGPRSTariffSwitchInterval;
    }

    @Override
    public Integer getROTimeGPRSSinceLastTariffSwitch() {
        return this.roTimeGPRSSinceLastTariffSwitch;
    }

    @Override
    public Integer getROTimeGPRSTariffSwitchInterval() {
        return this.roTimeGPRSTariffSwitchInterval;
    }

    public int getTag() throws CAPException {
        return _ID_ROTimeGPRSIfTariffSwitch;
    }

    public int getTagClass() {
        return Tag.CLASS_CONTEXT_SPECIFIC;
    }

    @Override
    protected void _decode(AsnInputStream asnIS, int length) throws CAPParsingComponentException, IOException, AsnException {

        this.roTimeGPRSSinceLastTariffSwitch = null;
        this.roTimeGPRSTariffSwitchInterval = null;

        AsnInputStream ais = asnIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_roTimeGPRSSinceLastTariffSwitch:
                        if (!ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".roTimeGPRSSinceLastTariffSwitch: Parameter is not primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.roTimeGPRSSinceLastTariffSwitch = (int) ais.readInteger();
                        break;
                    case _ID_roTimeGPRSTariffSwitchInterval:
                        if (!ais.isTagPrimitive())
                            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                                    + ".roTimeGPRSTariffSwitchInterval: Parameter is not primitive",
                                    CAPParsingComponentExceptionReason.MistypedParameter);
                        this.roTimeGPRSTariffSwitchInterval = (int) ais.readInteger();
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
    public void encodeData(AsnOutputStream asnOs) throws CAPException {

        try {
            if (this.roTimeGPRSSinceLastTariffSwitch != null)
                asnOs.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_roTimeGPRSSinceLastTariffSwitch,
                        this.roTimeGPRSSinceLastTariffSwitch.intValue());

            if (this.roTimeGPRSTariffSwitchInterval != null)
                asnOs.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, _ID_roTimeGPRSTariffSwitchInterval,
                        this.roTimeGPRSTariffSwitchInterval.intValue());

        } catch (IOException e) {
            throw new CAPException("IOException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName + " [");

        if (this.roTimeGPRSSinceLastTariffSwitch != null) {
            sb.append("roTimeGPRSSinceLastTariffSwitch=");
            sb.append(this.roTimeGPRSSinceLastTariffSwitch.toString());
            sb.append(", ");
        }

        if (this.roTimeGPRSTariffSwitchInterval != null) {
            sb.append("roTimeGPRSTariffSwitchInterval=");
            sb.append(this.roTimeGPRSTariffSwitchInterval.toString());
        }

        sb.append("]");

        return sb.toString();
    }
}
