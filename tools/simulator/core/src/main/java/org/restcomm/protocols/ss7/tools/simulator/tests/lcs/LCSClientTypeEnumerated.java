/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2018, Telestax Inc and individual contributors
 * by the @authors tag.
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

package org.restcomm.protocols.ss7.tools.simulator.tests.lcs;

import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientType;
import org.restcomm.protocols.ss7.tools.simulator.common.EnumeratedBase;

import java.util.Hashtable;

/**
 * @author <a href="mailto:serg.vetyutnev@gmail.com"> Sergey Vetyutnev </a>
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class LCSClientTypeEnumerated extends EnumeratedBase {

    private static Hashtable<String, Integer> stringMap = new Hashtable<String, Integer>();
    private static Hashtable<Integer, String> intMap = new Hashtable<Integer, String>();

    static {
        intMap.put(LCSClientType.emergencyServices.getType(), LCSClientType.emergencyServices.toString());
        intMap.put(LCSClientType.valueAddedServices.getType(), LCSClientType.valueAddedServices.toString());
        intMap.put(LCSClientType.plmnOperatorServices.getType(), LCSClientType.plmnOperatorServices.toString());
        intMap.put(LCSClientType.lawfulInterceptServices.getType(), LCSClientType.lawfulInterceptServices.toString());

        stringMap.put(LCSClientType.emergencyServices.toString(), LCSClientType.emergencyServices.getType());
        stringMap.put(LCSClientType.valueAddedServices.toString(), LCSClientType.valueAddedServices.getType());
        stringMap.put(LCSClientType.plmnOperatorServices.toString(), LCSClientType.plmnOperatorServices.getType());
        stringMap.put(LCSClientType.lawfulInterceptServices.toString(), LCSClientType.lawfulInterceptServices.getType());
    }

    public LCSClientTypeEnumerated() {
    }

    public LCSClientTypeEnumerated(int val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public LCSClientTypeEnumerated(Integer val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public LCSClientTypeEnumerated(String val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public static LCSClientTypeEnumerated createInstance(String s) {
        Integer instance = doCreateInstance(s, stringMap, intMap);
        if (instance == null)
            return new LCSClientTypeEnumerated(LCSClientType.emergencyServices.getType());
        else
            return new LCSClientTypeEnumerated(instance);
    }

    @Override
    protected Hashtable<Integer, String> getIntTable() {
        return intMap;
    }

    @Override
    protected Hashtable<String, Integer> getStringTable() {
        return stringMap;
    }
}
