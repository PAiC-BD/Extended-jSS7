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

package org.restcomm.protocols.ss7.sccp.impl.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SegmentationImpl;
import org.restcomm.protocols.ss7.sccp.parameter.HopCounter;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.sccp.parameter.Segmentation;

/**
 *
 * This interface represents a SCCP message for connectionless data transfer (UDT, XUDT and LUDT)
 *
 * @author sergey vetyutnev
 *
 */
public abstract class SccpSegmentableMessageImpl extends SccpAddressedMessageImpl {

    protected byte[] data;
    protected SegmentationImpl segmentation;

    protected boolean isFullyRecieved;
    protected int remainingSegments;
    protected ByteArrayOutputStream buffer;

    protected SccpStackImpl.MessageReassemblyProcess mrp;

    protected SccpSegmentableMessageImpl(int maxDataLen, int type, int outgoingSls, int localSsn,
            SccpAddress calledParty, SccpAddress callingParty, byte[] data, HopCounter hopCounter) {
        super(maxDataLen,type, outgoingSls, localSsn, calledParty, callingParty, hopCounter);

        this.data = data;
        this.isFullyRecieved = true;
    }

    protected SccpSegmentableMessageImpl(int maxDataLen, int type, int incomingOpc, int incomingDpc,
            int incomingSls, int networkId) {
        super(maxDataLen,type, incomingOpc, incomingDpc, incomingSls, networkId);
    }

    public Segmentation getSegmentation() {
        return segmentation;
    }

    public boolean getIsFullyRecieved() {
        return this.isFullyRecieved;
    }

    public int getRemainingSegments() {
        return remainingSegments;
    }

    public byte[] getData() {
        return this.data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public void setReceivedSingleSegment() {
        this.isFullyRecieved = true;
    }

    public void setReceivedFirstSegment() {
        if (this.segmentation == null)
            // this can not occur
            return;

        this.remainingSegments = this.segmentation.getRemainingSegments();
        this.buffer = new ByteArrayOutputStream(this.data.length * (this.remainingSegments + 1));
        try {
            this.buffer.write(this.data);
        } catch (IOException e) {
            // this can not occur
            e.printStackTrace();
        }
    }

    public void setReceivedNextSegment(SccpSegmentableMessageImpl nextSegement) {
        try {
            this.buffer.write(nextSegement.data);
        } catch (IOException e) {
            // this can not occur
            e.printStackTrace();
        }

        if (--this.remainingSegments == 0) {
            this.data = this.buffer.toByteArray();
            this.isFullyRecieved = true;
        }
    }

    public void cancelSegmentation() {
        this.remainingSegments = -1;
        this.isFullyRecieved = false;
    }

    public SccpStackImpl.MessageReassemblyProcess getMessageReassemblyProcess() {
        return mrp;
    }

    public void setMessageReassemblyProcess(SccpStackImpl.MessageReassemblyProcess mrp) {
        this.mrp = mrp;
    }
}
