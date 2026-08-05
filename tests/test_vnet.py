import time
import ipaddress
import json
import random
import time
import pytest

from swsscommon import swsscommon
from pprint import pprint
from dvslib.dvs_common import wait_for_result
from vnet_lib import *

class TestVnetOrch(object):

    CFG_SUBNET_DECAP_TABLE_NAME = "SUBNET_DECAP"

    @pytest.fixture
    def setup_subnet_decap(self, dvs):

        def _apply_subnet_decap_config(subnet_decap_config):
            """Apply subnet decap config to CONFIG_DB."""
            subnet_decap_tbl = swsscommon.Table(configdb, self.CFG_SUBNET_DECAP_TABLE_NAME)
            fvs = create_fvs(**subnet_decap_config)
            subnet_decap_tbl.set("AZURE", fvs)

        def _cleanup_subnet_decap_config():
            """Cleanup subnet decap config in CONFIG_DB."""
            subnet_decap_tbl = swsscommon.Table(configdb, self.CFG_SUBNET_DECAP_TABLE_NAME)
            for key in subnet_decap_tbl.getKeys():
                subnet_decap_tbl._del(key)

        configdb = swsscommon.DBConnector(swsscommon.CONFIG_DB, dvs.redis_sock, 0)
        _cleanup_subnet_decap_config()

        yield _apply_subnet_decap_config

        _cleanup_subnet_decap_config()

    def get_vnet_obj(self):
        return VnetVxlanVrfTunnel()

    def setup_db(self, dvs):
        self.pdb = dvs.get_app_db()
        self.adb = dvs.get_asic_db()
        self.cdb = dvs.get_config_db()
        self.sdb = dvs.get_state_db()

    def clear_srv_config(self, dvs):
        dvs.servers[0].runcmd("ip address flush dev eth0")
        dvs.servers[1].runcmd("ip address flush dev eth0")
        dvs.servers[2].runcmd("ip address flush dev eth0")
        dvs.servers[3].runcmd("ip address flush dev eth0")

    def set_admin_status(self, interface, status):
        self.cdb.update_entry("PORT", interface, {"admin_status": status})

    def create_l3_intf(self, interface, vrf_name):
        if len(vrf_name) == 0:
            self.cdb.create_entry("INTERFACE", interface, {"NULL": "NULL"})
        else:
            self.cdb.create_entry("INTERFACE", interface, {"vrf_name": vrf_name})

    def add_ip_address(self, interface, ip):
        self.cdb.create_entry("INTERFACE", interface + "|" + ip, {"NULL": "NULL"})

    def remove_ip_address(self, interface, ip):
        self.cdb.delete_entry("INTERFACE", interface + "|" + ip)

    def add_neighbor(self, interface, ip, mac):
        tbl = swsscommon.ProducerStateTable(self.pdb.db_connection, "NEIGH_TABLE")
        fvs = swsscommon.FieldValuePairs([("neigh", mac),
                                          ("family", "IPv4")])
        tbl.set(interface + ":" + ip, fvs)
        time.sleep(1)

    def remove_neighbor(self, interface, ip):
        tbl = swsscommon.ProducerStateTable(self.pdb.db_connection, "NEIGH_TABLE")
        tbl._del(interface + ":" + ip)
        time.sleep(1)

    def create_route_entry(self, key, pairs):
        tbl = swsscommon.ProducerStateTable(self.pdb.db_connection, "ROUTE_TABLE")
        fvs = swsscommon.FieldValuePairs(list(pairs.items()))
        tbl.set(key, fvs)

    def remove_route_entry(self, key):
        tbl = swsscommon.ProducerStateTable(self.pdb.db_connection, "ROUTE_TABLE")
        tbl._del(key)

    def check_route_entries(self, destinations):
        def _access_function():
            route_entries = self.adb.get_keys("ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY")
            route_destinations = [json.loads(route_entry)["dest"]
                                  for route_entry in route_entries]
            return (all(destination in route_destinations for destination in destinations), None)

        wait_for_result(_access_function)


    @pytest.fixture(params=["true", "false"])
    def ordered_ecmp(self, dvs, request):

        app_db = swsscommon.DBConnector(swsscommon.APPL_DB, dvs.redis_sock, 0)
        if request.param == "true":
            create_entry_pst(
                app_db,
                "SWITCH_TABLE", ':', "switch",
                [
                    ('ordered_ecmp', 'true')
                ],
            )
            dvs.get_state_db().wait_for_field_match("SWITCH_CAPABILITY", "switch", {"ORDERED_ECMP_CAPABLE": "true"})

        yield request.param

        if request.param == "true":
            create_entry_pst(
                app_db,
                "SWITCH_TABLE", ':', "switch",
                [
                    ('ordered_ecmp', 'false')
                ],
            )
            dvs.get_state_db().wait_for_field_match("SWITCH_CAPABILITY", "switch", {"ORDERED_ECMP_CAPABLE": "false"})


    '''
    Test 37: ECMP VNET local route with duplicate nexthop IP but different ifname, used for Link Local nexthops learned via FRR/BGP
    '''
    def test_vnet_local_route_ecmp_unnumbered(self, dvs, testlog):
        self.setup_db(dvs)

        vnet_obj = self.get_vnet_obj()

        tunnel_name = 'tunnel_ecmp_unified'
        vnet_name = "Vnet5099"
        prefix = "10.99.0.0/24"
        # Ethernet20 -> dvs.servers[5], Ethernet16 -> dvs.servers[4]
        if_a, srv_a = "Ethernet20", 5
        if_b, srv_b = "Ethernet16", 4
        nh_ip = "169.254.0.1"
        mac_a = "00:01:02:03:04:05"
        mac_b = "00:01:02:03:04:06"

        vnet_obj.fetch_exist_entries(dvs)

        create_vxlan_tunnel(dvs, tunnel_name, '99.99.99.99')
        create_vnet_entry(dvs, vnet_name, tunnel_name, '5099', "")
        vnet_obj.check_vnet_entry(dvs, vnet_name)
        vnet_obj.check_vxlan_tunnel_entry(dvs, tunnel_name, vnet_name, '5099')
        vnet_obj.check_vxlan_tunnel(dvs, tunnel_name, '99.99.99.99')

        create_phy_interface(dvs, if_a, vnet_name, "10.77.0.4/30")
        vnet_obj.check_router_interface(dvs, if_a, vnet_name)
        create_phy_interface(dvs, if_b, vnet_name, "10.77.0.8/30")
        vnet_obj.check_router_interface(dvs, if_b, vnet_name)

        self.set_admin_status(if_a, "up")
        self.set_admin_status(if_b, "up")

        self.add_neighbor(if_a, nh_ip, mac_a)
        self.add_neighbor(if_b, nh_ip, mac_b)

        vnet_obj.fetch_exist_entries(dvs)
        base_nhg  = len(vnet_obj.nhgs)
        base_nhgm = len(vnet_obj.nhgms)

        asic_db_conn = swsscommon.DBConnector(swsscommon.ASIC_DB, dvs.redis_sock, 0)
        route_tbl = swsscommon.Table(asic_db_conn, "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY")
        nhg_tbl   = swsscommon.Table(asic_db_conn, "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP")
        nh_tbl    = swsscommon.Table(asic_db_conn, "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP")
        rif_tbl   = swsscommon.Table(asic_db_conn, "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE")
        nhgm_tbl  = swsscommon.Table(asic_db_conn, "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER")
        port_name_map = dvs.get_counters_db().get_entry("COUNTERS_PORT_NAME_MAP", "")
        port_name_map = dict(port_name_map)

        def _rif_for_port(port_name):
            port_oid = port_name_map.get(port_name)
            assert port_oid, "no OID for %s" % port_name
            for rif_key in rif_tbl.getKeys():
                status, fvs = rif_tbl.get(rif_key)
                if status and dict(fvs).get("SAI_ROUTER_INTERFACE_ATTR_PORT_ID") == port_oid:
                    return rif_key
            assert False, "no RIF for port %s" % port_name

        def _nhgm_rifs(nhg_oid):
            rifs = set()
            for k in nhgm_tbl.getKeys():
                s, f = nhgm_tbl.get(k)
                f = dict(f)
                if f.get("SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID") == nhg_oid:
                    s2, nf = nh_tbl.get(f["SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID"])
                    rifs.add(dict(nf).get("SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID"))
            return rifs

        def _nh_rif(nh_oid):
            s, f = nh_tbl.get(nh_oid)
            return dict(f).get("SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID")

        def _wait_route_nh(expect_type, timeout=15):
            for _ in range(timeout * 2):
                route_keys = [k for k in route_tbl.getKeys() if prefix in k]
                if route_keys:
                    status, fvs = route_tbl.get(route_keys[0])
                    if status:
                        oid = dict(fvs).get("SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID")
                        if oid:
                            is_nhg = nhg_tbl.get(oid)[0]
                            is_nh  = nh_tbl.get(oid)[0]
                            if expect_type == "nhg" and is_nhg:
                                return oid
                            if expect_type == "nh" and is_nh and not is_nhg:
                                return oid
                time.sleep(0.5)
            assert False, "route %s NEXT_HOP_ID never resolved to a %s" % (prefix, expect_type)

        def _wait_nhgm_count(want_total, timeout=10):
            for _ in range(timeout * 2):
                vnet_obj.fetch_exist_entries(dvs)
                if len(vnet_obj.nhgms) == want_total:
                    return
                time.sleep(0.5)
            assert False, "NHG member count never reached %d (last: %d)" % (want_total, len(vnet_obj.nhgms))

        rif_a = _rif_for_port(if_a)
        rif_b = _rif_for_port(if_b)

        # ---- Phase A: 2 ifnames, duplicate IP -> 2-member NHG ----
        create_vnet_local_routes(dvs, prefix, vnet_name,
                                 '%s,%s' % (if_a, if_b),
                                 '%s,%s' % (nh_ip, nh_ip))
        vnet_obj.check_vnet_local_routes(dvs, vnet_name)
        nhg_oid_a = _wait_route_nh("nhg")
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg  + 1, "Phase A: NHG not created"
        assert len(vnet_obj.nhgms) == base_nhgm + 2, "Phase A: 2 NHG members expected"
        assert _nhgm_rifs(nhg_oid_a) == {rif_a, rif_b}, \
            "Phase A: NHG must contain distinct RIFs for %s and %s (duplicate-IP fix)" % (if_a, if_b)

        # ---- Phase B: shrink to 1 ifname -> NHG removed, single NH on rif_a ----
        create_vnet_local_routes(dvs, prefix, vnet_name, if_a, nh_ip)
        nh_oid_b = _wait_route_nh("nh")
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg, \
            "Phase B: NHG should be removed; delta %d" % (len(vnet_obj.nhgs) - base_nhg)
        assert len(vnet_obj.nhgms) == base_nhgm, \
            "Phase B: NHG members should be removed; delta %d" % (len(vnet_obj.nhgms) - base_nhgm)
        assert _nh_rif(nh_oid_b) == rif_a, \
            "Phase B: surviving NH must point at %s's RIF (rif_a=%s, got %s)" % (if_a, rif_a, _nh_rif(nh_oid_b))

        # ---- Phase C: grow back to 2 ifnames -> new 2-member NHG ----
        create_vnet_local_routes(dvs, prefix, vnet_name,
                                 '%s,%s' % (if_a, if_b),
                                 '%s,%s' % (nh_ip, nh_ip))
        nhg_oid_c = _wait_route_nh("nhg")
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg  + 1, "Phase C: NHG not re-created"
        assert len(vnet_obj.nhgms) == base_nhgm + 2, "Phase C: 2 NHG members expected"
        assert _nhgm_rifs(nhg_oid_c) == {rif_a, rif_b}, \
            "Phase C: reformed NHG must contain both RIFs"

        # ---- Phase D: implicit link-down. Flap veth carrier of if_b; PortsOrch
        # oper-status change -> NeighOrch.ifChangeInformNextHop ->
        # RouteOrch.invalidnexthopinNextHopGroup must prune the if_b member
        # NHG stays, drops to 1 member.
        dvs.servers[srv_b].runcmd("ip link set down dev eth0")
        self.set_admin_status(if_b, "down")
        _wait_nhgm_count(base_nhgm + 1)
        nhg_oid_d = _wait_route_nh("nhg")
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg + 1, \
            "Phase D: NHG must still exist with 1 member"
        assert _nhgm_rifs(nhg_oid_d) == {rif_a}, \
            "Phase D: surviving NHG member must be rif_a (got %s)" % _nhgm_rifs(nhg_oid_d)

        # ---- Phase E: bring if_b back up + re-learn neighbor -> NHG reforms ----
        dvs.servers[srv_b].runcmd("ip link set up dev eth0")
        self.set_admin_status(if_b, "up")
        self.add_neighbor(if_b, nh_ip, mac_b)
        _wait_nhgm_count(base_nhgm + 2)
        nhg_oid_e = _wait_route_nh("nhg")
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg  + 1, "Phase E: NHG should still exist"
        assert _nhgm_rifs(nhg_oid_e) == {rif_a, rif_b}, \
            "Phase E: NHG must again contain both RIFs"

        # ---- Cleanup ----
        delete_vnet_local_routes(dvs, prefix, vnet_name)
        vnet_obj.check_del_vnet_local_routes(dvs, vnet_name, prefix)
        vnet_obj.fetch_exist_entries(dvs)
        assert len(vnet_obj.nhgs)  == base_nhg
        assert len(vnet_obj.nhgms) == base_nhgm

        self.remove_neighbor(if_a, nh_ip)
        self.remove_neighbor(if_b, nh_ip)
        self.set_admin_status(if_a, "down")
        self.set_admin_status(if_b, "down")

        delete_phy_interface(dvs, if_a, "10.77.0.4/30")
        vnet_obj.check_del_router_interface(dvs, if_a)
        delete_phy_interface(dvs, if_b, "10.77.0.8/30")
        vnet_obj.check_del_router_interface(dvs, if_b)

        delete_vnet_entry(dvs, vnet_name)
        vnet_obj.check_del_vnet_entry(dvs, vnet_name)

        delete_vxlan_tunnel(dvs, tunnel_name)
        vnet_obj.check_del_vxlan_tunnel(dvs)


# Add Dummy always-pass test at end as workaroud
# for issue when Flaky fail on final test it invokes module tear-down before retrying
def test_nonflaky_dummy():
    pass
