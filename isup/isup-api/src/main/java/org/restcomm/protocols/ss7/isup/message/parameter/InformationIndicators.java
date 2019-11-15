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
 * Start time:13:16:08 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:13:16:08 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface InformationIndicators extends ISUPParameter {
    int _PARAMETER_CODE = 0x0F;

    /**
     * See Q.763 3.28 Calling party address response indicator : calling party address not included
     */
    int _CPARI_ADDRESS_NOT_INCLUDED = 0;

    /**
     * See Q.763 3.28 Calling party address response indicator : calling party address included
     */
    int _CPARI_ADDRESS_INCLUDED = 3;
    /**
     * See Q.763 3.28 Calling party address response indicator : calling party address not available
     */
    int _CPARI_ADDRESS_NOT_AVAILABLE = 1;

    /**
     * See Q.763 3.28 Hold provided indicator : hold not provided
     */
    boolean _HPI_NOT_PROVIDED = false;
    /**
     * See Q.763 3.28 Hold provided indicator : hold provided
     */
    boolean _HPI_PROVIDED = true;

    /**
     * See Q.763 3.28 Charge information response indicator : charge information not included
     */
    boolean _CIRI_NOT_INCLUDED = false;
    /**
     * See Q.763 3.28 Charge information response indicator : charge information included
     */
    boolean _CIRI_INCLUDED = true;

    /**
     * See Q.763 3.28 Solicited information indicator : solicited
     */
    boolean _SII_SOLICITED = false;
    /**
     * See Q.763 3.28 Solicited information indicator : unsolicited
     */
    boolean _SII_UNSOLICITED = true;
    /**
     * See Q.763 3.28 Calling party's category response indicator : calling party's category not included
     */
    boolean _CPCRI_CATEOGRY_NOT_INCLUDED = false;

    /**
     * See Q.763 3.28 Calling party's category response indicator : calling party's category not included
     */
    boolean _CPCRI_CATEOGRY_INCLUDED = true;

    int getCallingPartyAddressResponseIndicator();

    void setCallingPartyAddressResponseIndicator(int callingPartyAddressResponseIndicator);

    boolean isHoldProvidedIndicator();

    void setHoldProvidedIndicator(boolean holdProvidedIndicator);

    boolean isCallingPartysCategoryResponseIndicator();

    void setCallingPartysCategoryResponseIndicator(boolean callingPartysCategoryResponseIndicator);

    boolean isChargeInformationResponseIndicator();

    void setChargeInformationResponseIndicator(boolean chargeInformationResponseIndicator);

    boolean isSolicitedInformationIndicator();

    void setSolicitedInformationIndicator(boolean solicitedInformationIndicator);

    int getReserved();

    void setReserved(int reserved);

}
