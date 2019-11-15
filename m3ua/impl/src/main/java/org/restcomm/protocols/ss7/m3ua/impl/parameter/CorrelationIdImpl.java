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

package org.restcomm.protocols.ss7.m3ua.impl.parameter;

import org.restcomm.protocols.ss7.m3ua.parameter.CorrelationId;
import org.restcomm.protocols.ss7.m3ua.parameter.Parameter;

/**
 *
 * @author amit bhayani
 *
 */
public class CorrelationIdImpl extends ParameterImpl implements CorrelationId {

    private static final long UNSIGNED_INT_MAX_VALUE = 0xFFFFFFFF;
    private long corrId;

    protected CorrelationIdImpl(long corrId) {
        this.corrId = corrId;
        this.tag = Parameter.Correlation_ID;
    }

    protected CorrelationIdImpl(byte[] data) {
        this.corrId = 0;
        this.corrId |= data[0] & 0xFF;
        this.corrId <<= 8;
        this.corrId |= data[1] & 0xFF;
        this.corrId <<= 8;
        this.corrId |= data[2] & 0xFF;
        this.corrId <<= 8;
        this.corrId |= data[3] & 0xFF;
        this.tag = Parameter.Correlation_ID;
    }

    public long getCorrelationId() {
        return this.corrId;
    }

    @Override
    protected byte[] getValue() {
        byte[] data = new byte[4];
        data[0] = (byte) (corrId >>> 24);
        data[1] = (byte) (corrId >>> 16);
        data[2] = (byte) (corrId >>> 8);
        data[3] = (byte) (corrId);

        return data;
    }

    @Override
    public String toString() {
        return String.format("CorrelationId id=%d", corrId);
    }

}
