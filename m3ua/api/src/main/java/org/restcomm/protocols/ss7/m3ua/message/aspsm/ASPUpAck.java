/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.restcomm.protocols.ss7.m3ua.message.aspsm;

import org.restcomm.protocols.ss7.m3ua.message.M3UAMessage;
import org.restcomm.protocols.ss7.m3ua.parameter.ASPIdentifier;
import org.restcomm.protocols.ss7.m3ua.parameter.InfoString;

/**
 * The ASP UP Ack message is used to acknowledge an ASP Up message received from a remote M3UA peer. Both ASP Identifier and
 * INFO String are optional
 *
 * @author amit bhayani
 *
 */
public interface ASPUpAck extends M3UAMessage {

    ASPIdentifier getASPIdentifier();

    void setASPIdentifier(ASPIdentifier aspId);

    InfoString getInfoString();

    void setInfoString(InfoString str);
}
