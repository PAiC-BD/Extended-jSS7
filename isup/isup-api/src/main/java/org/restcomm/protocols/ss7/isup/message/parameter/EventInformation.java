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
 * Start time:12:47:23 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:12:47:23 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface EventInformation extends ISUPParameter {
    int _PARAMETER_CODE = 0x24;

    /**
     * See Q.763 3.21 Event indicator : ALERTING
     */
    int _EVENT_INDICATOR_ALERTING = 1;

    /**
     * See Q.763 3.21 Event indicator : PROGRESS
     */
    int _EVENT_INDICATOR_PROGRESS = 2;

    /**
     * See Q.763 3.21 Event indicator : in-band information or an appropriate pattern is now available
     */
    int _EVENT_INDICATOR_IIIOPA = 3;

    /**
     * See Q.763 3.21 Event indicator : call forwarded on busy (national use)
     */
    int _EVENT_INDICATOR_CFOB = 4;

    /**
     * See Q.763 3.21 Event indicator : call forwarded on no reply (national use)
     */
    int _EVENT_INDICATOR_CFONNR = 5;

    /**
     * See Q.763 3.21 Event indicator : call forwarded unconditional (national use)
     */
    int _EVENT_INDICATOR_CFOU = 6;

    /**
     * See Q.763 3.21 Event presentation restricted indicator (national use) : no indication
     */
    boolean _EVENT_PRESENTATION_INI = false;

    /**
     * See Q.763 3.21 Event presentation restricted indicator (national use) : presentation restricted
     */
    boolean _EVENT_PRESENTATION_IPR = true;

    int getEventIndicator();

    void setEventIndicator(int eventIndicator);

    boolean isEventPresentationRestrictedIndicator();

    void setEventPresentationRestrictedIndicator(boolean eventPresentationRestrictedIndicator);

}
