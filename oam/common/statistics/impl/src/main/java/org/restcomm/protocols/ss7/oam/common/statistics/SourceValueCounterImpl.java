/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
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

package org.restcomm.protocols.ss7.oam.common.statistics;

import org.restcomm.protocols.ss7.oam.common.statistics.api.CounterDef;
import org.restcomm.protocols.ss7.oam.common.statistics.api.SourceValueCounter;
import org.restcomm.protocols.ss7.oam.common.statistics.api.SourceValueObject;

import javolution.util.FastMap;

/**
*
* @author sergey vetyutnev
*
*/
public class SourceValueCounterImpl implements SourceValueCounter {

    private CounterDef counterDef;
    private FastMap<String, SourceValueObject> objects = new FastMap<String, SourceValueObject>();

    public SourceValueCounterImpl(CounterDef counterDef) {
        this.counterDef = counterDef;
    }

    public void addObject(SourceValueObject val) {
        objects.put(val.getObjectName(), val);
    }

    @Override
    public CounterDef getCounterDef() {
        return counterDef;
    }

    @Override
    public FastMap<String, SourceValueObject> getObjects() {
        return this.objects;
    }

    @Override
    public String toString() {
        return "SourceValueCounterImpl [counterDef=" + counterDef + ", objects=" + objects + "]";
    }

}
