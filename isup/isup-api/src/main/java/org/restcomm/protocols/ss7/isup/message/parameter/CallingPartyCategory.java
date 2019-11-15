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

package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:11:56:46 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface CallingPartyCategory extends ISUPParameter {
    int _PARAMETER_CODE = 0x09;

    /**
     * See Q.763 3.11
     */
    byte _CATEGORY_UNKNOWN = 0;

    /**
     * See Q.763 3.11 operator, language French
     */
    byte _CATEGORY_OL_FRENCH = 1;

    /**
     * See Q.763 3.11 operator, language English
     */
    byte _CATEGORY_OL_ENGLISH = 2;

    /**
     * See Q.763 3.11 operator, language German
     */
    byte _CATEGORY_OL_GERMAN = 3;

    /**
     * See Q.763 3.11 operator, language Russian
     */
    byte _CATEGORY_OL_RUSSIAN = 4;

    /**
     * See Q.763 3.11 operator, language Spanish
     */
    byte _CATEGORY_OL_SPANISH = 5;

    byte _OPERATOR_NATIONAL = 9;
    byte _ORDINARY_SUBSCRIBER = 10;
    byte _PRIORITY_SUBSCRIBER = 11;
    byte _DATA_CALL = 12;
    byte _TEST_CALL = 13;
    byte _PAYPHONE = 14;

    byte getCallingPartyCategory();

    void setCallingPartyCategory(byte callingPartyCategory);
}
