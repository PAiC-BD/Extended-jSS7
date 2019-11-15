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

package org.restcomm.protocols.ss7.sccp.impl.mgmt;

/**
 * Simple class to represent mtp3 primitive passed to sccp
 *
 * @author baranowb
 *
 */
public class Mtp3PrimitiveMessage {

    private int seq;
    private Mtp3PrimitiveMessageType type;
    private int affectedPc;
    private Mtp3UnavailabiltyCauseType unavailabiltyCause;
    private Mtp3StatusType status;
    private Mtp3CongestionType congestion;
    private long tstamp = System.currentTimeMillis();

    /**
     * @param seq
     * @param mtpParam
     * @param affectedPc
     */
    public Mtp3PrimitiveMessage(int seq, int mtpParam, int affectedPc) {
        this.seq = seq;
        this.type = Mtp3PrimitiveMessageType.fromInt(mtpParam);
        this.affectedPc = affectedPc;
    }

    /**
     * @param i
     * @param mtpParam
     * @param affectedPc2
     * @param status2
     * @param congStatus
     * @param unavailabiltyCause
     */
    public Mtp3PrimitiveMessage(int seq, int mtpParam, int affectedPc, int status, int congStatus, int unavailabiltyCause) {
        this(seq, mtpParam, affectedPc);
        this.status = Mtp3StatusType.fromInt(status);
        this.unavailabiltyCause = Mtp3UnavailabiltyCauseType.fromInt(unavailabiltyCause);
        this.congestion = Mtp3CongestionType.fromInt(congStatus);
    }

    /**
     * @param seq
     * @param type
     * @param affectedPc
     */
    public Mtp3PrimitiveMessage(int seq, Mtp3PrimitiveMessageType type, int affectedPc) {
        super();
        this.seq = seq;
        this.type = type;
        this.affectedPc = affectedPc;
    }

    public Mtp3PrimitiveMessage(int seq, Mtp3PrimitiveMessageType type, int affectedPc, Mtp3StatusType status,
            Mtp3CongestionType congStatus, Mtp3UnavailabiltyCauseType unavailabiltyCause) {
        this(seq, type, affectedPc);
        this.status = status;
        this.unavailabiltyCause = unavailabiltyCause;
        this.congestion = congStatus;
    }

    public int getSeq() {
        return seq;
    }

    public Mtp3PrimitiveMessageType getType() {
        return type;
    }

    public int getAffectedPc() {
        return affectedPc;
    }

    public Mtp3UnavailabiltyCauseType getUnavailabiltyCause() {
        return unavailabiltyCause;
    }

    public Mtp3StatusType getStatus() {
        return status;
    }

    public Mtp3CongestionType getCongestion() {
        return congestion;
    }

    public long getTstamp() {
        return tstamp;
    }

    public String toString() {
        return "Mtp3PrimitiveMessage [seq=" + seq + ", type=" + type + ", affectedPc=" + affectedPc + ", unavailabiltyCause="
                + unavailabiltyCause + ", status=" + status + ", congestion=" + congestion + ", tstamp=" + tstamp + "]";
    }

    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + affectedPc;
        result = prime * result + ((congestion == null) ? 0 : congestion.hashCode());
        result = prime * result + seq;
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((unavailabiltyCause == null) ? 0 : unavailabiltyCause.hashCode());
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Mtp3PrimitiveMessage other = (Mtp3PrimitiveMessage) obj;
        if (affectedPc != other.affectedPc)
            return false;
        if (congestion != other.congestion)
            return false;
        if (seq != other.seq)
            return false;
        if (status != other.status)
            return false;
        if (type != other.type)
            return false;
        if (unavailabiltyCause != other.unavailabiltyCause)
            return false;
        return true;
    }

}
