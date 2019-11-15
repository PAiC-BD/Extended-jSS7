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
import org.restcomm.protocols.ss7.cap.api.EsiBcsm.RouteSelectFailureSpecificInfo;
import org.restcomm.protocols.ss7.cap.api.isup.CauseCap;
import org.restcomm.protocols.ss7.cap.isup.CauseCapImpl;
import org.restcomm.protocols.ss7.cap.primitives.SequenceBase;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class RouteSelectFailureSpecificInfoImpl extends SequenceBase implements RouteSelectFailureSpecificInfo {

    private static final String CAUSE_CAP = "causeCap";

    public static final int _ID_failureCause = 0;

    private CauseCap failureCause;

    public RouteSelectFailureSpecificInfoImpl() {
        super("RouteSelectFailureSpecificInfo");
    }

    public RouteSelectFailureSpecificInfoImpl(CauseCap failureCause) {
        super("RouteSelectFailureSpecificInfo");
        this.failureCause = failureCause;
    }

    @Override
    public CauseCap getFailureCause() {
        return failureCause;
    }

    protected void _decode(AsnInputStream ansIS, int length) throws CAPParsingComponentException, MAPParsingComponentException,
            IOException, AsnException {

        this.failureCause = null;

        AsnInputStream ais = ansIS.readSequenceStreamData(length);
        while (true) {
            if (ais.available() == 0)
                break;

            int tag = ais.readTag();

            if (ais.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
                switch (tag) {
                    case _ID_failureCause:
                        this.failureCause = new CauseCapImpl();
                        ((CauseCapImpl) this.failureCause).decodeAll(ais);
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
    public void encodeData(AsnOutputStream aos) throws CAPException {
        if (this.failureCause != null) {
            ((CauseCapImpl) this.failureCause).encodeAll(aos, Tag.CLASS_CONTEXT_SPECIFIC, _ID_failureCause);
        }
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");
        if (this.failureCause != null) {
            sb.append("failureCause= {");
            sb.append(failureCause);
            sb.append("]");
        }
        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<RouteSelectFailureSpecificInfoImpl> ROUTE_SELECT_FAILURE_SPECIFIC_INFO_XML = new XMLFormat<RouteSelectFailureSpecificInfoImpl>(
            RouteSelectFailureSpecificInfoImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml,
                RouteSelectFailureSpecificInfoImpl routeSelectFailureSpecificInfo) throws XMLStreamException {
            routeSelectFailureSpecificInfo.failureCause = xml.get(CAUSE_CAP, CauseCapImpl.class);
        }

        @Override
        public void write(RouteSelectFailureSpecificInfoImpl routeSelectFailureSpecificInfo,
                javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {

            if (routeSelectFailureSpecificInfo.failureCause != null) {
                xml.add(((CauseCapImpl) routeSelectFailureSpecificInfo.failureCause), CAUSE_CAP, CauseCapImpl.class);
            }
        }
    };
}
