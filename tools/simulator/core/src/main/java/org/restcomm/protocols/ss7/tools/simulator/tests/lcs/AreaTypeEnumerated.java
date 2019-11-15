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

import org.restcomm.protocols.ss7.map.api.service.lsm.AreaType;
import org.restcomm.protocols.ss7.tools.simulator.common.EnumeratedBase;

import java.util.Hashtable;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 * @author <a href="mailto:falonso@csc.om"> Fernando Alonso </a>
 */
public class AreaTypeEnumerated extends EnumeratedBase {

    private static Hashtable<String, Integer> stringMap = new Hashtable<String, Integer>();
    private static Hashtable<Integer, String> intMap = new Hashtable<Integer, String>();

    static {
        intMap.put(AreaType.countryCode.getType(), AreaType.countryCode.toString());
        intMap.put(AreaType.plmnId.getType(), AreaType.plmnId.toString());
        intMap.put(AreaType.locationAreaId.getType(), AreaType.locationAreaId.toString());
        intMap.put(AreaType.routingAreaId.getType(), AreaType.routingAreaId.toString());
        intMap.put(AreaType.cellGlobalId.getType(), AreaType.cellGlobalId.toString());
        intMap.put(AreaType.utranCellId.getType(), AreaType.utranCellId.toString());
        stringMap.put(AreaType.countryCode.toString(), AreaType.countryCode.getType());
        stringMap.put(AreaType.plmnId.toString(), AreaType.plmnId.getType());
        stringMap.put(AreaType.locationAreaId.toString(), AreaType.locationAreaId.getType());
        stringMap.put(AreaType.routingAreaId.toString(), AreaType.routingAreaId.getType());
        stringMap.put(AreaType.cellGlobalId.toString(), AreaType.cellGlobalId.getType());
        stringMap.put(AreaType.utranCellId.toString(), AreaType.utranCellId.getType());
    }

    public AreaTypeEnumerated() {
    }

    public AreaTypeEnumerated(int val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public AreaTypeEnumerated(Integer val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public AreaTypeEnumerated(String val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public static AreaTypeEnumerated createInstance(String s) {
        Integer instance = doCreateInstance(s, stringMap, intMap);
        if (instance == null)
            return new AreaTypeEnumerated(AreaType.countryCode.getType());
        else
            return new AreaTypeEnumerated(instance);
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