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

package org.restcomm.protocols.ss7.map.api.service.lsm;

import java.io.Serializable;

import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;

/**
 * LCSCodeword ::= SEQUENCE { dataCodingScheme [0] USSD-DataCodingScheme, lcsCodewordString [1] LCSCodewordString, ...}
 *
 * LCSCodewordString ::= USSD-String (SIZE (1..20))
 *
 * @author amit bhayani
 *
 */
public interface LCSCodeword extends Serializable {

    /**
     * USSD-DataCodingScheme ::= OCTET STRING (SIZE (1)) -- The structure of the USSD-DataCodingScheme is defined by -- the Cell
     * Broadcast Data Coding Scheme as described in -- TS 3GPP TS 23.038 [25]
     *
     * @return
     */
    CBSDataCodingScheme getDataCodingScheme();

    /**
     * LCSCodewordString ::= USSD-String (SIZE (1..maxLCSCodewordStringLength))
     *
     * maxLCSCodewordStringLength INTEGER ::= 20
     *
     * @return
     */
    USSDString getLCSCodewordString();
}
