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
 * Start time:00:12:12 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.impl.message;

import org.restcomm.protocols.ss7.isup.ISUPParameterFactory;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.MessageTypeImpl;
import org.restcomm.protocols.ss7.isup.message.ChargeInformationMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageName;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageType;

/**
 * Start time:00:12:12 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class ChargeInformationMessageImpl extends ISUPMessageImpl implements ChargeInformationMessage {

    public static final MessageType _MESSAGE_TYPE = new MessageTypeImpl(MessageName.ChargeInformation);

    /**
     *
     * @param source
     * @throws ParameterException
     */
    public ChargeInformationMessageImpl() {

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.ISUPMessageImpl#decodeMandatoryVariableBody(byte[], int)
     */

    protected void decodeMandatoryVariableBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, int parameterIndex)
            throws ParameterException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.ISUPMessageImpl#decodeOptionalBody(byte[], byte)
     */

    protected void decodeOptionalBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, byte parameterCode)
            throws ParameterException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.ISUPMessageImpl#getMessageType()
     */

    public MessageType getMessageType() {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.ISUPMessageImpl#getNumberOfMandatoryVariableLengthParameters()
     */

    protected int getNumberOfMandatoryVariableLengthParameters() {
        // TODO Auto-generated method stub
        return 0;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.isup.ISUPMessageImpl#hasAllMandatoryParameters()
     */

    public boolean hasAllMandatoryParameters() {
        throw new UnsupportedOperationException();
    }

    protected boolean optionalPartIsPossible() {

        throw new UnsupportedOperationException();
    }

}
