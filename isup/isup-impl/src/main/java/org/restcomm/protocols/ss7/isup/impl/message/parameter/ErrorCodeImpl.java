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
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.ErrorCode;
import org.restcomm.protocols.ss7.isup.message.parameter.ErrorCodeType;


/**
 * @author baranowb
 * @author sergey netyutnev
 *
 */
public class ErrorCodeImpl extends AbstractAsnEncodable implements ErrorCode {
    private ErrorCodeType type;
    private Long localErrorCode;
    private long[] globalErrorCode;

    public void setErrorCodeType(ErrorCodeType type) {
        this.type = type;
    }

    public void setLocalErrorCode(Long localErrorCode) {
        this.localErrorCode = localErrorCode;
        this.globalErrorCode = null;
        this.type = ErrorCodeType.Local;
    }

    public void setGlobalErrorCode(long[] globalErrorCode) {
        this.localErrorCode = null;
        this.globalErrorCode = globalErrorCode;
        this.type = ErrorCodeType.Global;
    }

    public Long getLocalErrorCode() {
        return this.localErrorCode;
    }

    public long[] getGlobalErrorCode() {
        return this.globalErrorCode;
    }

    public ErrorCodeType getErrorType() {
        return type;
    }

    public String toString() {
        if (this.localErrorCode != null)
            return "ErrorCode[errorType=Local, data=" + this.localErrorCode.toString() + "]";
        else if (this.globalErrorCode != null)
            return "ErrorCode[errorType=Global, data=" + Arrays.toString(this.globalErrorCode) + "]";
        else
            return "ErrorCode[empty]";
    }

    public void decode(AsnInputStream ais) throws ParameterException {

        try {
            if (this.type == ErrorCodeType.Global) {
                this.globalErrorCode = ais.readObjectIdentifier();
            } else if (this.type == ErrorCodeType.Local) {
                this.localErrorCode = ais.readInteger();
            } else {
                throw new ParameterException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new ParameterException("IOException while parsing ErrorCode: "
                    + e.getMessage(), e);
        } catch (AsnException e) {
            e.printStackTrace();
            throw new ParameterException(
                    "AsnException while parsing ErrorCode: " + e.getMessage(), e);
        }
    }

    public void encode(AsnOutputStream aos) throws ParameterException {

        if (this.localErrorCode == null && this.globalErrorCode == null)
            throw new ParameterException("Error code: No error code set!");

        try {
            if (this.type == ErrorCodeType.Local) {
                aos.writeInteger(this.localErrorCode);
            } else if (this.type == ErrorCodeType.Global) {
                aos.writeObjectIdentifier(this.globalErrorCode);
            } else {
                throw new ParameterException();
            }
        } catch (IOException e) {
            throw new ParameterException(e);
        } catch (AsnException e) {
            throw new ParameterException(e);
        }
    }

}
