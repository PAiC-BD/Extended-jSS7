/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
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

package org.restcomm.protocols.ss7.sccp.impl;

import javolution.xml.XMLFormat;
import javolution.xml.XMLSerializable;
import javolution.xml.stream.XMLStreamException;

import org.restcomm.protocols.ss7.sccp.RemoteSignalingPointCode;

/**
 * @author amit bhayani
 * @author sergey vetyutnev
 *
 */
public class RemoteSignalingPointCodeImpl implements XMLSerializable, RemoteSignalingPointCode {
    private static final String REMOTE_SPC = "remoteSpc";
    private static final String REMOTE_SPC_FLAG = "remoteSpcFlag";
    private static final String MASK = "mask";

    private int remoteSpc;
    private int remoteSpcFlag;
    private int mask;
    protected boolean remoteSpcProhibited;
    protected boolean remoteSccpProhibited;

    protected int rl;
    protected int rsl;

    private RemoteSignalingPointCodeExt remoteSignalingPointCodeExt;

    public RemoteSignalingPointCodeImpl() {
    }

    public RemoteSignalingPointCodeImpl(int remoteSpc, int remoteSpcFlag, int mask, boolean isProhibited) {
        this.remoteSpc = remoteSpc;
        this.remoteSpcFlag = remoteSpcFlag;
        this.mask = mask;
        this.remoteSccpProhibited = isProhibited;
        this.remoteSpcProhibited = isProhibited;
    }

    public void createRemoteSignalingPointCodeExt(Ss7ExtSccpDetailedInterface ss7ExtSccpDetailedInterface) {
        remoteSignalingPointCodeExt = ss7ExtSccpDetailedInterface.createRemoteSignalingPointCodeExt(this);
    }

    public RemoteSignalingPointCodeExt getRemoteSignalingPointCodeExt() {
        return remoteSignalingPointCodeExt;
    }

    public int getRemoteSpc() {
        return remoteSpc;
    }

    public int getRemoteSpcFlag() {
        return remoteSpcFlag;
    }

    public int getMask() {
        return mask;
    }

    public boolean isRemoteSpcProhibited() {
        return remoteSpcProhibited;
    }

    public boolean isRemoteSccpProhibited() {
        return remoteSccpProhibited;
    }

    protected void setProhibitedState(boolean remoteSpcProhibited, boolean remoteSccpProhibited) {
        this.remoteSpcProhibited = remoteSpcProhibited;
        this.remoteSccpProhibited = remoteSccpProhibited;
    }

    protected void setRemoteSpcProhibited(boolean remoteSpcProhibited) {
        this.remoteSpcProhibited = remoteSpcProhibited;
    }

    protected void setRemoteSccpProhibited(boolean remoteSccpProhibited) {
        this.remoteSccpProhibited = remoteSccpProhibited;
    }

    /**
     * @param remoteSpc the remoteSpc to set
     */
    protected void setRemoteSpc(int remoteSpc) {
        this.remoteSpc = remoteSpc;
    }

    /**
     * @param remoteSpcFlag the remoteSpcFlag to set
     */
    protected void setRemoteSpcFlag(int remoteSpcFlag) {
        this.remoteSpcFlag = remoteSpcFlag;
    }

    /**
     * @param mask the mask to set
     */
    protected void setMask(int mask) {
        this.mask = mask;
    }

    @Override
    public int getCurrentRestrictionLevel() {
        return rl;
    }

    public int getCurrentRestrictionSubLevel() {
        return rsl;
    }

    void clearCongLevel() {
        remoteSignalingPointCodeExt.clearCongLevel();
    }

    void increaseCongLevel(int level) {
        remoteSignalingPointCodeExt.increaseCongLevel(level);
    }

    /**
     * Do not use this method directly except of debugging. Use clearCongLevel(), increaseCongLevel(), decreaseCongLevel()
     *
     * @param value
     */
    public void setCurrentRestrictionLevel(int value) {
        this.rl = value;
        this.rsl = 0;
    }

    public void setRl(int val) {
        rl = val;
    }

    public void setRsl(int val) {
        rsl = val;
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("rsp=").append(this.remoteSpc).append(" rsp-flag=").append(this.remoteSpcFlag).append(" mask=")
                .append(this.mask).append(" rsp-prohibited=").append(this.remoteSpcProhibited).append(" rsccp-prohibited=")
                .append(this.remoteSccpProhibited).append(" rl=").append(rl).append(" rsl=").append(rsl);
        return sb.toString();
    }

    protected static final XMLFormat<RemoteSignalingPointCodeImpl> XML = new XMLFormat<RemoteSignalingPointCodeImpl>(
            RemoteSignalingPointCodeImpl.class) {

        public void write(RemoteSignalingPointCodeImpl ai, OutputElement xml) throws XMLStreamException {
            xml.setAttribute(REMOTE_SPC, ai.remoteSpc);
            xml.setAttribute(REMOTE_SPC_FLAG, ai.remoteSpcFlag);
            xml.setAttribute(MASK, ai.mask);

        }

        public void read(InputElement xml, RemoteSignalingPointCodeImpl ai) throws XMLStreamException {
            ai.remoteSpc = xml.getAttribute(REMOTE_SPC).toInt();
            ai.remoteSpcFlag = xml.getAttribute(REMOTE_SPC_FLAG).toInt();
            ai.mask = xml.getAttribute(MASK).toInt();
        }
    };

}
