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
 * Start time:13:06:26 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski
 *         </a>
 *
 */
package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.CalledINNumber;

/**
 * Start time:13:06:26 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class CalledINNumberImpl extends CalledNumberImpl implements CalledINNumber {

    /**
     * @param representation
     */
    public CalledINNumberImpl(byte[] representation) throws ParameterException {
        super(representation);

    }

    /**
     * @param bis
     */
    public CalledINNumberImpl(ByteArrayInputStream bis) throws ParameterException {
        super(bis);

    }

    public CalledINNumberImpl() {
        super();

    }

    /**
     * @param natureOfAddresIndicator
     * @param address
     * @param numberingPlanIndicator
     * @param addressRepresentationREstrictedIndicator
     */
    public CalledINNumberImpl(int natureOfAddresIndicator, String address, int numberingPlanIndicator,
            int addressRepresentationREstrictedIndicator) {
        super(natureOfAddresIndicator, address, numberingPlanIndicator, addressRepresentationREstrictedIndicator);

    }

    protected String getPrimitiveName() {
        return "CalledINNumber";
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
