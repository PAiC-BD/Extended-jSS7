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

package org.restcomm.protocols.ss7.sccp.impl.parameter;

import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.message.ParseException;
import org.restcomm.protocols.ss7.sccp.parameter.ParameterFactory;
import org.restcomm.protocols.ss7.sccp.parameter.ReceiveSequenceNumber;
import org.restcomm.protocols.ss7.sccp.parameter.SequenceNumber;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ReceiveSequenceNumberImpl extends AbstractParameter implements ReceiveSequenceNumber {
    private SequenceNumber value = new SequenceNumberImpl(0);

    public ReceiveSequenceNumberImpl() {
    }

    public ReceiveSequenceNumberImpl(SequenceNumber value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value.getValue();
    }

    public SequenceNumber getNumber() {
        return value;
    }

    public void setNumber(SequenceNumber value) {
        this.value = value;
    }

    @Override
    public void decode(final InputStream in, final ParameterFactory factory, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        this.value = new SequenceNumberImpl(0);
        try {
            if (in.read() != 1) {
                throw new ParseException();
            }
            this.value = new SequenceNumberImpl((byte)(in.read() >> 1 & 0x7F));
        } catch (IOException ioe) {
            throw new ParseException(ioe);
        }
    }

    @Override
    public void encode(final OutputStream os, final boolean removeSpc, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        try {
            os.write(1);
            os.write(this.value.getValue() << 1 & 0xFE);
        } catch (IOException ioe) {
            throw new ParseException(ioe);
        }
    }

    @Override
    public void decode(final byte[] b, final ParameterFactory factory, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        if (b.length < 1) {
            throw new ParseException();
        }
        this.value = new SequenceNumberImpl((byte)(b[0] >> 1 & 0x7F));

    }

    @Override
    public byte[] encode(final boolean removeSpc, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        return new byte[] {
                (byte) (this.value.getValue() << 1 & 0xFE)
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ReceiveSequenceNumberImpl that = (ReceiveSequenceNumberImpl) o;

        return value == that.value;

    }

    @Override
    public int hashCode() {
        return value.getValue();
    }

    @Override
    public String toString() {
        return new StringBuffer().append("ReceiveSequenceNumber [").append("value=").append(value.getValue()).append("]").toString();
    }
}
