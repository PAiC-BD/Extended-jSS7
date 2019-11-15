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

import org.restcomm.protocols.ss7.m3ua.parameter.Parameter;
import org.restcomm.protocols.ss7.m3ua.parameter.Status;

/**
 *
 * @author amit bhayani
 *
 */
public class StatusImpl extends ParameterImpl implements Status {

    private int type;
    private int info;

    public StatusImpl(int type, int info) {
        this.type = type;
        this.info = info;
        this.tag = Parameter.Status;
    }

    public StatusImpl(byte[] data) {
        this.tag = Parameter.Status;

        this.type = 0;
        this.type |= data[0] & 0xFF;
        this.type <<= 8;
        this.type |= data[1] & 0xFF;

        this.info = 0;
        this.info |= data[2] & 0xFF;
        this.info <<= 8;
        this.info |= data[3] & 0xFF;

    }

    @Override
    protected byte[] getValue() {
        byte[] data = new byte[4];
        data[0] = (byte) (type >>> 8);
        data[1] = (byte) (type);

        data[2] = (byte) (info >>> 8);
        data[3] = (byte) (info);

        return data;
    }

    public int getInfo() {
        return this.info;
    }

    public int getType() {
        return this.type;
    }

    @Override
    public String toString() {
        return String.format("Status type=%d info=%d", type, info);
    }

}
