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

import java.util.UUID;

import org.restcomm.protocols.ss7.oam.common.statistics.api.SourceValueCounter;
import org.restcomm.protocols.ss7.oam.common.statistics.api.SourceValueSet;

import javolution.util.FastMap;

/**
*
* @author sergey vetyutnev
*
*/
public class SourceValueSetImpl implements SourceValueSet {

    private UUID sessionId;
    private FastMap<String, SourceValueCounter> counters = new FastMap<String, SourceValueCounter>();

    public void addCounter(SourceValueCounter val) {
        this.counters.put(val.getCounterDef().getCounterName(), val);
    }

    public SourceValueSetImpl(UUID sessionId) {
        this.sessionId = sessionId;
    }

    @Override
    public UUID getSessionId() {
        return sessionId;
    }

    @Override
    public FastMap<String, SourceValueCounter> getCounters() {
        return this.counters;
    }

    @Override
    public String toString() {
        return "SourceValueSetImpl [sessionId=" + sessionId + ", counters size=" + counters.size() + "]";
    }

}
