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

package org.restcomm.protocols.ss7.map.api.service.oam;

import java.io.Serializable;

/**
 *
<code>
SGW-InterfaceList ::= BIT STRING {
  s4 (0),
  s5 (1),
  s8b (2),
  s11 (3),
  gxc (4)
} (SIZE (5..8))
-- Other bits than listed above shall be discarded.
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface SGWInterfaceList extends Serializable {

    boolean getS4();

    boolean getS5();

    boolean getS8b();

    boolean getS11();

    boolean getGxc();

}
