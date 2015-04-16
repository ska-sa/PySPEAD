/* packet-interlink.c
 * Routines for SPEAD packet disassembly
 * By Simon Ratcliffe <sratcliffe@ska.ac.za>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <stdio.h>
#define SPEAD_PORT 7148

static int proto_spead = -1;
static int hf_spead_magic = -1;
static int hf_spead_version = -1;
static int hf_spead_itemwidth = -1;
static int hf_spead_heapwidth = -1;
static int hf_spead_items = -1;
static int hf_spead_item_mode = -1;
static int hf_spead_item_id = -1;
static int hf_spead_item_val = -1;
static int spead_header = -1;
static int spead_items = -1;
static gint ett_spead = -1;
static gint ett_header = -1;
static gint ett_items = -1;
static gint ett_item = -1;

static const value_string item_identifiers[] = {
 { 0x0000, "NULL - Ignore" },
 { 0x0001, "Heap Counter" },
 { 0x0002, "Heap Size" },
 { 0x0003, "Heap Offset" },
 { 0x0004, "Packet Payload Length" },
 { 0x0005, "Item Descriptor" },
 { 0x0006, "Stream Control" },
 { 0x0010, "Item Descriptor: Name" },
 { 0x0011, "Item Descriptor: Description" },
 { 0x0012, "Item Descriptor: Shape" },
 { 0x0013, "Item Descriptor: Type" },
 { 0x0014, "Item Descriptor: ID" }
};

static void
dissect_spead(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i, offset, no_items;
    guint tvb_len;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPEAD");
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_item *items_sub_item = NULL;
        proto_item *item_sub_item = NULL;
        proto_item *header_sub_item = NULL;
        proto_tree *spead_tree = NULL;
        proto_tree *header_tree = NULL;
        proto_tree *items_tree = NULL;
        proto_tree *item_tree = NULL;

        ti = proto_tree_add_item(tree, proto_spead, tvb, 0, -1, FALSE);
        spead_tree = proto_item_add_subtree(ti, ett_spead);
        header_sub_item = proto_tree_add_item(spead_tree, spead_header, tvb, 0, -1, FALSE);
        items_sub_item = proto_tree_add_item(spead_tree, spead_items, tvb, 0, -1, FALSE);
        header_tree = proto_item_add_subtree(header_sub_item, ett_header);
        items_tree = proto_item_add_subtree(items_sub_item, ett_items);

        proto_tree_add_item(header_tree, hf_spead_magic, tvb, 0, 1, FALSE);
        proto_tree_add_item(header_tree, hf_spead_version, tvb, 1, 1, FALSE);
        proto_tree_add_item(header_tree, hf_spead_itemwidth, tvb, 2, 1, FALSE);
        proto_tree_add_item(header_tree, hf_spead_heapwidth, tvb, 3, 1, FALSE);
        proto_tree_add_item(header_tree, hf_spead_items, tvb, 6, 2, FALSE);
        no_items = (tvb_get_guint8(tvb, 6) >> 8) + tvb_get_guint8(tvb, 7);
         // get the number of items in this header
        offset = 8;
        for (i=0; i < no_items; i++) {
         item_sub_item = proto_tree_add_item(items_tree, hf_spead_item_id, tvb, offset+0, 2, FALSE);
         item_tree = proto_item_add_subtree(item_sub_item, ett_item);
         proto_tree_add_uint_format(item_tree, hf_spead_item_mode, tvb, offset, 1, tvb_get_guint8(tvb,7),
        "Item Adress Mode: %s", (tvb_get_guint8(tvb,offset) & 0x80) ? "Immediate" : "Absolute");
         proto_tree_add_item(item_tree, hf_spead_item_val, tvb, offset+2, 6, FALSE);
         offset+=8;
        }

        tvb_len = tvb_reported_length(tvb);
        proto_tree_add_text(spead_tree, tvb, offset, -1, "Heap (%i Bytes)", tvb_len - offset);
    }
}

void
proto_register_spead(void)
{
    static hf_register_info hf[] = {
         {&spead_items, {"Items", "spead.items", FT_NONE, BASE_NONE, NULL, 0x0, "Items", HFILL }},
         {&spead_header, {"Header", "spead.header", FT_NONE, BASE_NONE, NULL, 0x0, "Header", HFILL }},
         {&hf_spead_magic, { "SPEAD Magic", "spead.magic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
         {&hf_spead_version, { "SPEAD Version", "spead.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
         {&hf_spead_itemwidth, { "SPEAD Item Pointer Width", "spead.itempointerwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
         {&hf_spead_heapwidth, { "SPEAD Heap Address Width", "spead.heapaddresswidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
         {&hf_spead_items, { "SPEAD # of Items", "spead.items", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
         {&hf_spead_item_mode, {"Mode", "spead.item.mode", FT_UINT8, BASE_HEX, 0, 0x0, NULL, HFILL }},
         {&hf_spead_item_id, { "ID", "spead.item.identifier", FT_UINT16, BASE_HEX, VALS(item_identifiers), 0x0, NULL, HFILL }},
         {&hf_spead_item_val, { "Value", "spead.item.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_spead,
        &ett_header,
        &ett_items,
        &ett_item
    };

    proto_spead = proto_register_protocol (
        "Streaming Protocol for Exchanging Astronomical Data",
        "SPEAD",
        "spead"
        );
    proto_register_field_array(proto_spead, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_spead(void)
{
    static dissector_handle_t spead_handle;

    spead_handle = create_dissector_handle(dissect_spead, proto_spead);
    dissector_add_uint("udp.port", SPEAD_PORT, spead_handle);
}
