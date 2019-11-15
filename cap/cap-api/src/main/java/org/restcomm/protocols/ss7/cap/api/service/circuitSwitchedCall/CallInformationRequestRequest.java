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

package org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall;

import java.util.ArrayList;

import org.restcomm.protocols.ss7.cap.api.primitives.CAPExtensions;
import org.restcomm.protocols.ss7.cap.api.primitives.SendingSideID;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.RequestedInformationType;

/**
 *
 callInformationRequest {PARAMETERS-BOUND : bound} OPERATION ::= { ARGUMENT CallInformationRequestArg {bound} RETURN RESULT
 * FALSE ERRORS {missingParameter | parameterOutOfRange | requestedInfoError | systemFailure | taskRefused |
 * unexpectedComponentSequence | unexpectedDataValue | unexpectedParameter | unknownLegID} CODE opcode-callInformationRequest}
 * -- Direction: gsmSCF -> gsmSSF, Timer: Tcirq -- This operation is used to request the gsmSSF to record specific information
 * about a single -- call party and report it to the gsmSCF (with a CallInformationReport operation).
 *
 * CallInformationRequestArg {PARAMETERS-BOUND : bound}::= SEQUENCE { requestedInformationTypeList [0]
 * RequestedInformationTypeList, extensions [2] Extensions {bound} OPTIONAL, legID [3] SendingSideID DEFAULT sendingSideID:leg2,
 * ... } -- OPTIONAL denotes network operator optional.
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface CallInformationRequestRequest extends CircuitSwitchedCallMessage {

    ArrayList<RequestedInformationType> getRequestedInformationTypeList();

    CAPExtensions getExtensions();

    SendingSideID getLegID();

}