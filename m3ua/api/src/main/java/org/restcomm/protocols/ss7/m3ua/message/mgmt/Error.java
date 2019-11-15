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

package org.restcomm.protocols.ss7.m3ua.message.mgmt;

import org.restcomm.protocols.ss7.m3ua.message.M3UAMessage;
import org.restcomm.protocols.ss7.m3ua.parameter.AffectedPointCode;
import org.restcomm.protocols.ss7.m3ua.parameter.DiagnosticInfo;
import org.restcomm.protocols.ss7.m3ua.parameter.ErrorCode;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;

/**
 * The Error message is used to notify a peer of an error event associated with an incoming message. For example, the message
 * type might be unexpected given the current state, or a parameter value might be invalid. Error messages MUST NOT be generated
 * in response to other Error messages.
 *
 * @author amit bhayani
 *
 */
public interface Error extends M3UAMessage {

    ErrorCode getErrorCode();

    void setErrorCode(ErrorCode code);

    RoutingContext getRoutingContext();

    void setRoutingContext(RoutingContext rc);

    NetworkAppearance getNetworkAppearance();

    void setNetworkAppearance(NetworkAppearance netApp);

    AffectedPointCode getAffectedPointCode();

    void setAffectedPointCode(AffectedPointCode affPc);

    DiagnosticInfo getDiagnosticInfo();

    void setDiagnosticInfo(DiagnosticInfo diagInfo);

}
