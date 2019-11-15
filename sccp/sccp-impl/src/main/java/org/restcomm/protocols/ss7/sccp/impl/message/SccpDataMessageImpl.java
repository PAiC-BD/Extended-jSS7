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

import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.impl.parameter.AbstractParameter;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ProtocolClassImpl;
import org.restcomm.protocols.ss7.sccp.message.ParseException;
import org.restcomm.protocols.ss7.sccp.message.SccpDataMessage;
import org.restcomm.protocols.ss7.sccp.message.SccpMessage;
import org.restcomm.protocols.ss7.sccp.parameter.HopCounter;
import org.restcomm.protocols.ss7.sccp.parameter.Importance;
import org.restcomm.protocols.ss7.sccp.parameter.ProtocolClass;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;

/**
 *
 * This class represents a SCCP message for connectionless data transfer (UDT, XUDT and LUDT)
 *
 * @author Oleg Kulikov
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public class SccpDataMessageImpl extends SccpDataNoticeTemplateMessageImpl implements SccpDataMessage {

    protected ProtocolClass protocolClass;

    /**
     * Create a SCCP-User originated message
     *
     * @param protocolClass
     * @param outgoingSls
     * @param calledParty
     * @param callingParty
     * @param data
     * @param hopCounter This parameter may be null if you use the max value
     * @param importance This parameter may be null if you use the default value
     */
    protected SccpDataMessageImpl(int maxDataLen, ProtocolClass protocolClass, int outgoingSls, int localSsn,
            SccpAddress calledParty, SccpAddress callingParty, byte[] data, HopCounter hopCounter, Importance importance) {
        super(maxDataLen, SccpMessage.MESSAGE_TYPE_UNDEFINED, outgoingSls, localSsn, calledParty, callingParty, data,
                hopCounter, importance);

        this.protocolClass = protocolClass;
    }

    /**
     * Create a MTP3 originated message
     *
     * @param incomingOpc
     * @param incomingDpc
     * @param incomingSls
     */
    protected SccpDataMessageImpl(int maxDataLen, int type, int incomingOpc, int incomingDpc, int incomingSls, int networkId) {
        super(maxDataLen, type, incomingOpc, incomingDpc, incomingSls, networkId);
    }

    public ProtocolClass getProtocolClass() {
        return protocolClass;
    }

    public void setProtocolClass(ProtocolClass protocolClass) {
        this.protocolClass = protocolClass;
    }

    public boolean getReturnMessageOnError() {
        if (this.protocolClass != null)
            return this.protocolClass.getReturnMessageOnError();
        else
            return false;
    }

    public void clearReturnMessageOnError() {
        if (this.protocolClass != null)
            this.protocolClass.clearReturnMessageOnError();
    }

    public boolean getSccpCreatesSls() {
        if (this.protocolClass == null || this.protocolClass.getProtocolClass() == 0)
            return true;
        else
            return false;
    }

    @Override
    protected boolean getSecondParamaterPresent() {
        return protocolClass != null;
    }

    @Override
    protected byte[] getSecondParamaterData(boolean removeSPC, SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        return ((AbstractParameter) protocolClass).encode(removeSPC, sccpProtocolVersion);
    }

    @Override
    protected void setSecondParamaterData(int data, SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        protocolClass = new ProtocolClassImpl();
        // TODO, this makes no sense.
        ((AbstractParameter) protocolClass).decode(new byte[] { (byte) data }, null, sccpProtocolVersion);
    }

    @Override
    protected boolean getIsProtocolClass1() {
        return this.protocolClass.getProtocolClass() != 0;
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("Sccp Msg [Type=");
        switch (this.type) {
            case SccpMessage.MESSAGE_TYPE_UDT:
                sb.append("UDT");
                break;
            case SccpMessage.MESSAGE_TYPE_XUDT:
                sb.append("XUDT");
                break;
            case SccpMessage.MESSAGE_TYPE_LUDT:
                sb.append("LUDT");
                break;
            default:
                sb.append(this.type);
                break;
        }
        sb.append(" networkId=").append(this.networkId).append(" sls=").append(this.sls).append(" incomingOpc=").append(this.incomingOpc)
                .append(" incomingDpc=").append(this.incomingDpc).append(" outgoingDpc=").append(this.outgoingDpc).append(" CallingAddress(")
                .append(this.callingParty).append(") CalledParty(").append(this.calledParty).append(")");
        if (this.importance != null) {
            sb.append(" importance=");
            sb.append(this.importance.getValue());
        }
        if (this.hopCounter != null) {
            sb.append(" hopCounter=");
            sb.append(this.hopCounter.getValue());
        }
        if (this.segmentation != null) {
            sb.append(" segmentation=");
            sb.append(this.segmentation.toString());
        }
        sb.append(" DataLen=");
        if (this.data != null)
            sb.append(this.data.length);
        sb.append("]");
        return sb.toString();
    }
}
