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
 * Start time:13:52:59 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:13:52:59 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 * This RangeAndStatus indiactes whcih CICs, starting from one present in message are affected. Range indicates how many CICs
 * are potentially affected. Status contains bits indicating CIC affected(1 - affected, 0 - not affected) <br>
 * For content interpretation refer to Q.763 3.43
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface RangeAndStatus extends ISUPParameter {

    int _PARAMETER_CODE = 0x16;

    /**
     * Fetches range.
     *
     * @return
     */
    byte getRange();

    /**
     * Sets range.
     *
     * @param range
     * @param addStatus - flag indicates if implementation should create proper status
     */
    void setRange(byte range, boolean addStatus);

    /**
     * Sets range.
     *
     * @param range
     */
    void setRange(byte range);

    /**
     * Gets raw status part.
     *
     * @return
     */
    byte[] getStatus();

    /**
     * Gets raw status part.
     *
     * @return
     */
    void setStatus(byte[] status);

    void setAffected(byte subrange, boolean v) throws IllegalArgumentException;

    boolean isAffected(byte b) throws IllegalArgumentException;
}
