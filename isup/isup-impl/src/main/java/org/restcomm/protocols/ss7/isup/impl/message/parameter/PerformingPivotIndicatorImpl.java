/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

/**
 * Start time:09:09:20 2009-04-06<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski
 *         </a>
 *
 */
package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.InformationType;
import org.restcomm.protocols.ss7.isup.message.parameter.PerformingPivotIndicator;
import org.restcomm.protocols.ss7.isup.message.parameter.PivotReason;

/**
 * Start time:09:09:20 2009-04-06<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class PerformingPivotIndicatorImpl extends AbstractInformationImpl implements PerformingPivotIndicator {

    private List<PivotReason> reasons = new ArrayList<PivotReason>();

    public PerformingPivotIndicatorImpl() {
        super(InformationType.PerformingPivotIndicator);
        super.tag = 0x03;
    }

    @Override
    public void setReason(PivotReason... reasons) {
        this.reasons.clear();
        if(reasons == null){
            return;
        }
        for(PivotReason pr: reasons){
            if(pr!=null){
                this.reasons.add(pr);
            }
        }
    }

    @Override
    public PivotReason[] getReason() {
        return this.reasons.toArray(new PivotReason[this.reasons.size()]);
    }

    @Override
    byte[] encode() throws ParameterException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for(PivotReason pr:this.reasons){
            PivotReasonImpl ai = (PivotReasonImpl) pr;
            try {
                baos.write(ai.encode());
            } catch (IOException e) {
                throw new ParameterException(e);
            }
        }
        return baos.toByteArray();
    }

    @Override
    void decode(byte[] data) throws ParameterException {
        for(int index = 0;index<data.length;index++){
            byte b = data[index];
            PivotReasonImpl pr = new PivotReasonImpl();
            pr.setPivotReason((byte) (b & 0x7F));
            if( (b & 0x80) == 0){
                if (index +1 == data.length){
                    throw new ParameterException("Extension bit incicates more bytes, but we ran out of them!");
                }
                b = data[++index];
                pr.setPivotPossibleAtPerformingExchange((byte) (b & 0x07));
            }
            this.reasons.add(pr);
        }
    }

}
