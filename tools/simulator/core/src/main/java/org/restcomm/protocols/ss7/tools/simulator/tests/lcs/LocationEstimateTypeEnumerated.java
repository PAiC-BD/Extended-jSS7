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

import org.restcomm.protocols.ss7.map.api.service.lsm.LocationEstimateType;
import org.restcomm.protocols.ss7.tools.simulator.common.EnumeratedBase;

import java.util.Hashtable;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 * @author <a href="mailto:falonso@csc.om"> Fernando Alonso </a>
 */
public class LocationEstimateTypeEnumerated extends EnumeratedBase {

    private static Hashtable<String, Integer> stringMap = new Hashtable<String, Integer>();
    private static Hashtable<Integer, String> intMap = new Hashtable<Integer, String>();

    static {
        intMap.put(LocationEstimateType.currentLocation.getType(), LocationEstimateType.currentLocation.toString());
        intMap.put(LocationEstimateType.currentOrLastKnownLocation.getType(), LocationEstimateType.currentOrLastKnownLocation.toString());
        intMap.put(LocationEstimateType.initialLocation.getType(), LocationEstimateType.initialLocation.toString());
        intMap.put(LocationEstimateType.activateDeferredLocation.getType(), LocationEstimateType.activateDeferredLocation.toString());
        intMap.put(LocationEstimateType.cancelDeferredLocation.getType(), LocationEstimateType.cancelDeferredLocation.toString());

        stringMap.put(LocationEstimateType.currentLocation.toString(), LocationEstimateType.currentLocation.getType());
        stringMap.put(LocationEstimateType.currentOrLastKnownLocation.toString(), LocationEstimateType.currentOrLastKnownLocation.getType());
        stringMap.put(LocationEstimateType.initialLocation.toString(), LocationEstimateType.initialLocation.getType());
        stringMap.put(LocationEstimateType.activateDeferredLocation.toString(), LocationEstimateType.activateDeferredLocation.getType());
        stringMap.put(LocationEstimateType.cancelDeferredLocation.toString(), LocationEstimateType.cancelDeferredLocation.getType());
    }

    public LocationEstimateTypeEnumerated() {
    }

    public LocationEstimateTypeEnumerated(int val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public LocationEstimateTypeEnumerated(Integer val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public LocationEstimateTypeEnumerated(String val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public static LocationEstimateTypeEnumerated createInstance(String s) {
        Integer instance = doCreateInstance(s, stringMap, intMap);
        if (instance == null)
            return new LocationEstimateTypeEnumerated(LocationEstimateType.currentLocation.getType());
        else
            return new LocationEstimateTypeEnumerated(instance);
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
