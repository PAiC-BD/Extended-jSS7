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

package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.IOException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.GeneralProblemType;
import org.restcomm.protocols.ss7.isup.message.parameter.InvokeProblemType;
import org.restcomm.protocols.ss7.isup.message.parameter.Problem;
import org.restcomm.protocols.ss7.isup.message.parameter.ProblemType;
import org.restcomm.protocols.ss7.isup.message.parameter.ReturnErrorProblemType;
import org.restcomm.protocols.ss7.isup.message.parameter.ReturnResultProblemType;


/**
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public class ProblemImpl extends AbstractAsnEncodable implements Problem {

    private ProblemType type;

    private GeneralProblemType generalProblemType;
    private InvokeProblemType invokeProblemType;
    private ReturnErrorProblemType returnErrorProblemType;
    private ReturnResultProblemType returnResultProblemType;

    /**
     * @return the type
     */
    public ProblemType getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(ProblemType type) {
        this.type = type;
    }

    /**
     * @return the generalProblemType
     */
    public GeneralProblemType getGeneralProblemType() {
        return generalProblemType;
    }

    /**
     * @param generalProblemType the generalProblemType to set
     */
    public void setGeneralProblemType(GeneralProblemType generalProblemType) {
        this.generalProblemType = generalProblemType;
        this.setType(ProblemType.General);
    }

    /**
     * @return the invokeProblemType
     */
    public InvokeProblemType getInvokeProblemType() {
        return invokeProblemType;
    }

    /**
     * @param invokeProblemType the invokeProblemType to set
     */
    public void setInvokeProblemType(InvokeProblemType invokeProblemType) {
        this.setType(ProblemType.Invoke);
        this.invokeProblemType = invokeProblemType;
    }

    /**
     * @return the returnErrorProblemType
     */
    public ReturnErrorProblemType getReturnErrorProblemType() {
        return returnErrorProblemType;
    }

    /**
     * @param returnErrorProblemType the returnErrorProblemType to set
     */
    public void setReturnErrorProblemType(ReturnErrorProblemType returnErrorProblemType) {
        this.returnErrorProblemType = returnErrorProblemType;
        this.setType(ProblemType.ReturnError);
    }

    /**
     * @return the returnResultProblemType
     */
    public ReturnResultProblemType getReturnResultProblemType() {
        return returnResultProblemType;
    }

    /**
     * @param returnResultProblemType the returnResultProblemType to set
     */
    public void setReturnResultProblemType(ReturnResultProblemType returnResultProblemType) {
        this.returnResultProblemType = returnResultProblemType;
        this.setType(ProblemType.ReturnResult);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Problem[type=");
        sb.append(type);
        sb.append(" ");
        switch (type) {
            case General:
                sb.append("generalProblemType=");
                sb.append(this.generalProblemType);
                break;
            case Invoke:
                sb.append("invokeProblemType=");
                sb.append(this.invokeProblemType);
                break;
            case ReturnResult:
                sb.append("returnResultProblemType=");
                sb.append(this.returnResultProblemType);
                break;
            case ReturnError:
                sb.append("returnErrorProblemType=");
                sb.append(this.returnErrorProblemType);
                break;
        }
        sb.append("]");

        return sb.toString();
    }

    public void decode(AsnInputStream ais) throws ParameterException {

        try {
            long t = ais.readInteger();

            switch (type) {
                case General:
                    this.generalProblemType = GeneralProblemType.getFromInt(t);
                    break;
                case Invoke:
                    this.invokeProblemType = InvokeProblemType.getFromInt(t);
                    break;
                case ReturnError:
                    this.returnErrorProblemType = ReturnErrorProblemType.getFromInt(t);
                    break;
                case ReturnResult:
                    this.returnResultProblemType = ReturnResultProblemType.getFromInt(t);
                    break;
                default:
                    // should not happen
                    throw new ParameterException();
            }

        } catch (IOException e) {
            throw new ParameterException("IOException while decoding Problem: "
                    + e.getMessage(), e);
        } catch (AsnException e) {
            throw new ParameterException("AsnException while decoding Problem: "
                    + e.getMessage(), e);
        }

    }

    public void encode(AsnOutputStream aos) throws ParameterException {

        try {

            switch (type) {
                case General:
                    if (this.generalProblemType == null)
                        throw new ParameterException("Problem Type is General, no specific type set");

                    aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, (int) type.getTypeTag(), this.generalProblemType.getType());
                    break;

                case Invoke:
                    if (this.invokeProblemType == null)
                        throw new ParameterException("Problem Type is Invoke, no specific type set");
                    aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, (int) type.getTypeTag(), this.invokeProblemType.getType());
                    break;

                case ReturnError:
                    if (this.returnErrorProblemType == null)
                        throw new ParameterException("Problem Type is ReturnError, no specific type set");
                    aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, (int) type.getTypeTag(), this.returnErrorProblemType.getType());
                    break;

                case ReturnResult:
                    if (this.returnResultProblemType == null)
                        throw new ParameterException("Problem Type is Result, no specific type set");
                    aos.writeInteger(Tag.CLASS_CONTEXT_SPECIFIC, (int) type.getTypeTag(),
                            this.returnResultProblemType.getType());
                    break;

                default:
                    // should not happen
                    throw new ParameterException();
            }

        } catch (IOException e) {
            throw new ParameterException("IOException while encoding Problem: " + e.getMessage(), e);
        } catch (AsnException e) {
            throw new ParameterException("AsnException while encoding Problem: " + e.getMessage(), e);
        }

    }

}
