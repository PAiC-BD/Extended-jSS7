/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.restcomm.protocols.ss7.m3ua.message.ssnm;

import org.restcomm.protocols.ss7.m3ua.message.M3UAMessage;
import org.restcomm.protocols.ss7.m3ua.parameter.AffectedPointCode;
import org.restcomm.protocols.ss7.m3ua.parameter.ConcernedDPC;
import org.restcomm.protocols.ss7.m3ua.parameter.CongestedIndication;
import org.restcomm.protocols.ss7.m3ua.parameter.InfoString;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;

/**
 * <p>
 * The Signalling Congestion SCON message can be sent from an SGP to all concerned ASPs to indicate that an SG has determined
 * that there is congestion in the SS7 network to one or more destinations, or to an ASP in response to a DATA or DAUD message,
 * as appropriate. For some MTP protocol variants (e.g., ANSI MTP) the SCON message may be sent when the SS7 congestion level
 * changes. The SCON message MAY also be sent from the M3UA layer of an ASP to an M3UA peer, indicating that the congestion
 * level of the M3UA layer or the ASP has changed.
 * </p>
 *
 * @author amit bhayani
 *
 */
public interface SignallingCongestion extends M3UAMessage {

    NetworkAppearance getNetworkAppearance();

    void setNetworkAppearance(NetworkAppearance p);

    RoutingContext getRoutingContexts();

    void setRoutingContexts(RoutingContext routingCntx);

    AffectedPointCode getAffectedPointCodes();

    void setAffectedPointCodes(AffectedPointCode afpcs);

    ConcernedDPC getConcernedDPC();

    void setConcernedDPC(ConcernedDPC dpc);

    CongestedIndication getCongestedIndication();

    void setCongestedIndication(CongestedIndication congInd);

    InfoString getInfoString();

    void setInfoString(InfoString str);

}
