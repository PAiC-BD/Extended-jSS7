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

package org.restcomm.protocols.ss7.cap.EsiBcsm;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.EsiBcsm.TDisconnectSpecificInfo;
import org.restcomm.protocols.ss7.cap.api.isup.CauseCap;
import org.restcomm.protocols.ss7.cap.isup.CauseCapImpl;
import org.restcomm.protocols.ss7.cap.primitives.SequenceBase;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class TDisconnectSpecificInfoImpl extends SequenceBase implements TDisconnectSpecificInfo {

    private static final String RELEASE_CAUSE = "releaseCause";

    public static final int _ID_releaseCause = 0;

    private CauseCap releaseCause;

    public TDisconnectSpecificInfoImpl() {
        super("TDisconnectSpecificInfo");
    }

    public TDisconnectSpecificInfoImpl(CauseCap releaseCause) {
        super("TDisconnectSpecificInfo");
        this.releaseCause = releaseCause;
    }

    @Override
    public CauseCap getReleaseCause() {
        return releaseCause;
    }

    protected void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, MAPParsingComponentException,
            IOException, AsnException {

        this.releaseCause = null;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_releaseCause:
                        this.releaseCause = new CauseCapImpl();
                        ((CauseCapImpl) this.releaseCause).decodeAll(ais);
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
        if (this.releaseCause != null) {
            ((CauseCapImpl) this.releaseCause).encodeAll(asnOs, Tag.CLASS_CONTEXT_SPECIFIC, _ID_releaseCause);
        }
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");
        if (this.releaseCause != null) {
            sb.append("releaseCause= [");
            sb.append(releaseCause);
            sb.append("]");
        }
        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<TDisconnectSpecificInfoImpl> ROUTE_SELECT_FAILURE_SPECIFIC_INFO_XML = new XMLFormat<TDisconnectSpecificInfoImpl>(
            TDisconnectSpecificInfoImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, TDisconnectSpecificInfoImpl oCalledPartyBusySpecificInfo)
                throws XMLStreamException {
            oCalledPartyBusySpecificInfo.releaseCause = xml.get(RELEASE_CAUSE, CauseCapImpl.class);
        }

        @Override
        public void write(TDisconnectSpecificInfoImpl oCalledPartyBusySpecificInfo, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {

            if (oCalledPartyBusySpecificInfo.releaseCause != null) {
                xml.add(((CauseCapImpl) oCalledPartyBusySpecificInfo.releaseCause), RELEASE_CAUSE, CauseCapImpl.class);
            }
        }
    };
}
