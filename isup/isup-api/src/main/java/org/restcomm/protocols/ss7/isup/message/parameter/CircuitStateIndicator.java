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
 * Start time:12:22:51 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:12:22:51 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface CircuitStateIndicator extends ISUPParameter {
    int _PARAMETER_CODE = 0x26;

    // FIXME: Q.763 3.14 - Oleg is this correct?

    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state "0" : transient
     */
    int _MBS_NPS_TRANSIENT = 0;

    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state "0" : unequipped
     */
    int _MBS_NPS_UNEQUIPED = 3;

    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state ~"0" : no blocking - active
     */
    int _MBS_NO_BLOCKING = 0;

    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state ~"0" : localy blocked
     */
    int _MBS_LOCALY_BLOCKED = 1;
    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state ~"0" : remotely blocked blocked
     */
    int _MBS_REMOTELY_BLOCKED = 2;

    /**
     * See Q.763 3.14 Maintenance blocking state - for call processing state ~"0" : locally and remotely blocked
     */
    int _MBS_LAR_BLOCKED = 3;

    /**
     * See Q.763 3.14 Call processing state : circuit incoming busy
     */
    int _CPS_CIB = 1;
    /**
     * See Q.763 3.14 Call processing state : circuit outgoing busy
     */
    int _CPS_COB = 2;
    /**
     * See Q.763 3.14 Call processing state : idle
     */
    int _CPS_IDLE = 3;

    /**
     * See Q.763 3.14 Hardware blocking state (Note: if this does not equal "0" Call Processing State must be equal to "3") : no
     * blocking (active)
     */
    int _HBS_NO_BLOCKING = 0;
    /**
     * See Q.763 3.14 Hardware blocking state (Note: if this does not equal "0" Call Processing State must be equal to "3") :
     * locally blocked
     */
    int _HBS_LOCALY_BLOCKED = 1;
    /**
     * See Q.763 3.14 Hardware blocking state (Note: if this does not equal "0" Call Processing State must be equal to "3") :
     * remotely blocked
     */
    int _HBS_REMOTELY_BLOCKED = 2;
    /**
     * See Q.763 3.14 Hardware blocking state (Note: if this does not equal "0" Call Processing State must be equal to "3") :
     * locally and remotely blocked
     */
    int _HBS_LAR_BLOCKED = 3;

    byte[] getCircuitState();

    void setCircuitState(byte[] circuitState) throws IllegalArgumentException;

    byte createCircuitState(int MBS, int CPS, int HBS);

    int getCallProcessingState(byte b);

    int getHardwareBlockingState(byte b);

    int getMaintenanceBlockingState(byte b);

}
