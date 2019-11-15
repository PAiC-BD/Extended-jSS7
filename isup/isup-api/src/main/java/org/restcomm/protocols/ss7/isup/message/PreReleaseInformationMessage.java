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

package org.restcomm.protocols.ss7.isup.message;

import org.restcomm.protocols.ss7.isup.message.parameter.ApplicationTransport;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageCompatibilityInformation;
import org.restcomm.protocols.ss7.isup.message.parameter.OptionalBackwardCallIndicators;
import org.restcomm.protocols.ss7.isup.message.parameter.OptionalForwardCallIndicators;
import org.restcomm.protocols.ss7.isup.message.parameter.ParameterCompatibilityInformation;

/**
 * Start time:09:54:07 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface PreReleaseInformationMessage extends ISUPMessage {
    /**
     * Pre-release information Message, Q.763 reference table 52 <br>
     * {@link PreReleaseInformationMessage}
     */
    int MESSAGE_CODE = 0x42;

    MessageCompatibilityInformation getMessageCompatibilityInformation();

    void setMessageCompatibilityInformation(MessageCompatibilityInformation mci);

    ParameterCompatibilityInformation getParameterCompatibilityInformation();

    void setParameterCompatibilityInformation(ParameterCompatibilityInformation pci);

    OptionalForwardCallIndicators getOptionalForwardCallIndicators();

    void setOptionalForwardCallIndicators(OptionalForwardCallIndicators obci);

    OptionalBackwardCallIndicators getOptionalBackwardCallIndicators();

    void setOptionalBackwardCallIndicators(OptionalBackwardCallIndicators obci);

    ApplicationTransport getApplicationTransport();

    void setApplicationTransport(ApplicationTransport at);
}
