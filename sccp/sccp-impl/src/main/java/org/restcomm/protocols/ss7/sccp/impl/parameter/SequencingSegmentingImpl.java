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
import org.restcomm.protocols.ss7.sccp.parameter.SequenceNumber;
import org.restcomm.protocols.ss7.sccp.parameter.SequencingSegmenting;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SequencingSegmentingImpl extends AbstractParameter implements SequencingSegmenting {

    private SequenceNumber sendSequenceNumber = new SequenceNumberImpl(0);
    private SequenceNumber receiveSequenceNumber = new SequenceNumberImpl(0);
    private boolean moreData;

    public SequencingSegmentingImpl() {
    }

    public SequencingSegmentingImpl(SequenceNumber sendSequenceNumber, SequenceNumber receiveSequenceNumber, boolean moreData) {
        this.sendSequenceNumber = sendSequenceNumber;
        this.receiveSequenceNumber = receiveSequenceNumber;
        this.moreData = moreData;
    }

    @Override
    public SequenceNumber getSendSequenceNumber() {
        return sendSequenceNumber;
    }

    @Override
    public void setSendSequenceNumber(SequenceNumber sendSequenceNumber) {
        this.sendSequenceNumber = sendSequenceNumber;
    }

    @Override
    public SequenceNumber getReceiveSequenceNumber() {
        return receiveSequenceNumber;
    }

    @Override
    public void setReceiveSequenceNumber(SequenceNumber receiveSequenceNumber) {
        this.receiveSequenceNumber = receiveSequenceNumber;
    }

    @Override
    public boolean isMoreData() {
        return moreData;
    }

    @Override
    public void setMoreData(boolean moreData) {
        this.moreData = moreData;
    }

    @Override
    public void decode(final InputStream in, final ParameterFactory factory, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        try {
            if (in.read() != 2) {
                throw new ParseException();
            }
            this.sendSequenceNumber = new SequenceNumberImpl((byte)(in.read() >> 1 & 0x7F));
            int secondOctet = in.read();
            this.receiveSequenceNumber = new SequenceNumberImpl((byte)(secondOctet >> 1 & 0x7F));
            this.moreData = (secondOctet & 0x01) == 1;
        } catch (IOException ioe) {
            throw new ParseException(ioe);
        }
    }

    @Override
    public void encode(final OutputStream os, final boolean removeSpc, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        try {
            os.write(2);
            os.write(this.sendSequenceNumber.getValue() << 1 & 0xFE);
            os.write(this.receiveSequenceNumber.getValue() << 1 & 0xFE | ((moreData) ? 1 : 0));
        } catch (IOException ioe) {
            throw new ParseException(ioe);
        }
    }

    @Override
    public void decode(final byte[] b, final ParameterFactory factory, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        if (b.length < 2) {
            throw new ParseException();
        }
        this.sendSequenceNumber = new SequenceNumberImpl((byte)(b[0] >> 1 & 0x7F));
        this.receiveSequenceNumber = new SequenceNumberImpl((byte)(b[1] >> 1 & 0x7F));
        this.moreData = (b[1] & 0x01) == 1;
    }

    @Override
    public byte[] encode(final boolean removeSpc, final SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        return new byte[] {
                (byte) (this.sendSequenceNumber.getValue() << 1 & 0xFE),
                (byte) (this.receiveSequenceNumber.getValue() << 1 & 0xFE | ((moreData) ? 1 : 0))
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SequencingSegmentingImpl that = (SequencingSegmentingImpl) o;

        if (sendSequenceNumber != that.sendSequenceNumber) return false;
        if (receiveSequenceNumber != that.receiveSequenceNumber) return false;
        return moreData == that.moreData;

    }

    @Override
    public int hashCode() {
        int result = sendSequenceNumber.getValue();
        result = 31 * result + receiveSequenceNumber.getValue();
        result = 31 * result + (moreData ? 1 : 0);
        return result;
    }

    public String toString() {
        return new StringBuffer().append("SequencingSegmenting [").append("ps=").append(sendSequenceNumber.getValue()).append(",pr=")
                .append(receiveSequenceNumber.getValue()).append(",moreData=").append(moreData).append("]").toString();
    }
}
