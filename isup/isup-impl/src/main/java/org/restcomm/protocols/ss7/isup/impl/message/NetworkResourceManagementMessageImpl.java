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
 * Start time:00:11:10 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.impl.message;

import java.util.Map;
import java.util.Set;

import org.restcomm.protocols.ss7.isup.ISUPParameterFactory;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.MessageTypeImpl;
import org.restcomm.protocols.ss7.isup.message.NetworkResourceManagementMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.EchoControlInformation;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageCompatibilityInformation;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageName;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageType;
import org.restcomm.protocols.ss7.isup.message.parameter.ParameterCompatibilityInformation;

/**
 * Start time:00:11:10 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class NetworkResourceManagementMessageImpl extends ISUPMessageImpl implements NetworkResourceManagementMessage {

    public static final MessageType _MESSAGE_TYPE = new MessageTypeImpl(MessageName.NetworkResourceManagement);
    private static final int _MANDATORY_VAR_COUNT = 0;
    private static final boolean _HAS_MANDATORY = true;
    private static final boolean _OPTIONAL_POSSIBLE = true;

    static final int _INDEX_F_MessageType = 0;

    static final int _INDEX_O_MessageCompatibilityInformation = 0;
    static final int _INDEX_O_ParameterCompatibilityInformation = 1;
    static final int _INDEX_O_EchoControlInformation = 2;
    static final int _INDEX_O_EndOfOptionalParameters = 3;

    /**
     *
     * @param source
     * @throws ParameterException
     */
    public NetworkResourceManagementMessageImpl(Set<Integer> mandatoryCodes, Set<Integer> mandatoryVariableCodes,
            Set<Integer> optionalCodes, Map<Integer, Integer> mandatoryCode2Index,
            Map<Integer, Integer> mandatoryVariableCode2Index, Map<Integer, Integer> optionalCode2Index) {
        super(mandatoryCodes, mandatoryVariableCodes, optionalCodes, mandatoryCode2Index, mandatoryVariableCode2Index,
                optionalCode2Index);
        super.f_Parameters.put(_INDEX_F_MessageType, this.getMessageType());
        super.o_Parameters.put(_INDEX_O_EndOfOptionalParameters, _END_OF_OPTIONAL_PARAMETERS);
    }

    protected void decodeMandatoryVariableBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, int parameterIndex)
            throws ParameterException {

    }

    protected void decodeOptionalBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, byte parameterCode)
            throws ParameterException {
        switch (parameterCode & 0xFF) {
            case MessageCompatibilityInformation._PARAMETER_CODE:
                MessageCompatibilityInformation mci = parameterFactory.createMessageCompatibilityInformation();
                ((AbstractISUPParameter) mci).decode(parameterBody);
                this.setMessageCompatibilityInformation(mci);
                break;
            case ParameterCompatibilityInformation._PARAMETER_CODE:
                ParameterCompatibilityInformation pci = parameterFactory.createParameterCompatibilityInformation();
                ((AbstractISUPParameter) pci).decode(parameterBody);
                this.setParameterCompatibilityInformation(pci);
                break;
            case EchoControlInformation._PARAMETER_CODE:
                EchoControlInformation ro = parameterFactory.createEchoControlInformation();
                ((AbstractISUPParameter) ro).decode(parameterBody);
                this.setEchoControlInformation(ro);
                break;
            default:
                throw new ParameterException("Unrecognized parameter code for optional part: " + parameterCode);
        }

    }

    public MessageType getMessageType() {
        return _MESSAGE_TYPE;
    }

    protected int getNumberOfMandatoryVariableLengthParameters() {
        return _MANDATORY_VAR_COUNT;
    }

    public boolean hasAllMandatoryParameters() {
        return _HAS_MANDATORY;
    }

    protected boolean optionalPartIsPossible() {
        return _OPTIONAL_POSSIBLE;
    }

    @Override
    public MessageCompatibilityInformation getMessageCompatibilityInformation() {
        return (MessageCompatibilityInformation) super.o_Parameters.get(_INDEX_O_MessageCompatibilityInformation);
    }

    @Override
    public void setMessageCompatibilityInformation(MessageCompatibilityInformation mci) {
        super.o_Parameters.put(_INDEX_O_MessageCompatibilityInformation, mci);
    }

    @Override
    public ParameterCompatibilityInformation getParameterCompatibilityInformation() {
        return (ParameterCompatibilityInformation) super.o_Parameters.get(_INDEX_O_ParameterCompatibilityInformation);
    }

    @Override
    public void setParameterCompatibilityInformation(ParameterCompatibilityInformation pci) {
        super.o_Parameters.put(_INDEX_O_ParameterCompatibilityInformation, pci);
    }

    @Override
    public EchoControlInformation getEchoControlInformation() {
        return (EchoControlInformation) super.o_Parameters.get(_INDEX_O_EchoControlInformation);
    }

    @Override
    public void setEchoControlInformation(EchoControlInformation pci) {
        super.o_Parameters.put(_INDEX_O_EchoControlInformation, pci);
    }
}
