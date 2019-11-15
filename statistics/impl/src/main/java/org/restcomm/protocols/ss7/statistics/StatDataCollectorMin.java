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

package org.restcomm.protocols.ss7.statistics;

import org.restcomm.protocols.ss7.statistics.api.StatDataCollectorType;

/**
*
* @author sergey vetyutnev
*
*/
public class StatDataCollectorMin extends StatDataCollectorLongImpl {

    public StatDataCollectorMin(String name) {
        super(name);
    }

    @Override
    protected void reset() {
        val = Long.MAX_VALUE;
    }

    @Override
    public void updateData(long newVal) {
        if (val > newVal)
            val = newVal;
    }

    @Override
    public StatDataCollectorType getStatDataCollectorType() {
        return StatDataCollectorType.MIN;
    }

    @Override
    public void updateData(String newVal) {
    }

}
