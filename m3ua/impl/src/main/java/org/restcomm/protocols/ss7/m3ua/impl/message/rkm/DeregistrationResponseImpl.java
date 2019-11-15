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

package org.restcomm.protocols.ss7.m3ua.impl.message.rkm;

import io.netty.buffer.ByteBuf;

import org.restcomm.protocols.ss7.m3ua.impl.message.M3UAMessageImpl;
import org.restcomm.protocols.ss7.m3ua.impl.parameter.ParameterImpl;
import org.restcomm.protocols.ss7.m3ua.message.MessageClass;
import org.restcomm.protocols.ss7.m3ua.message.MessageType;
import org.restcomm.protocols.ss7.m3ua.message.rkm.DeregistrationResponse;
import org.restcomm.protocols.ss7.m3ua.parameter.DeregistrationResult;
import org.restcomm.protocols.ss7.m3ua.parameter.Parameter;

/**
 *
 * @author amit bhayani
 *
 */
public class DeregistrationResponseImpl extends M3UAMessageImpl implements DeregistrationResponse {

    public DeregistrationResponseImpl() {
        super(MessageClass.ROUTING_KEY_MANAGEMENT, MessageType.DEREG_RESPONSE, MessageType.S_DEREG_RESPONSE);
    }

    @Override
    protected void encodeParams(ByteBuf buf) {
        ((ParameterImpl) parameters.get(Parameter.Deregistration_Result)).write(buf);
    }

    public DeregistrationResult getDeregistrationResult() {
        return (DeregistrationResult) parameters.get(Parameter.Deregistration_Result);
    }

    public void setDeregistrationResult(DeregistrationResult result) {
        parameters.put(Parameter.Deregistration_Result, result);

    }

}
