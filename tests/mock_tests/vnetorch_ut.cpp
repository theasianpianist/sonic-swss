#include "ut_helper.h"
#include "mock_orchagent_main.h"
#include "mock_sai_api.h"
#include "mock_sai_tunnel.h"
#include "mock_orch_test.h"
#include "common/mock_test_helpers.h"

#include <gtest/gtest.h>

EXTERN_MOCK_FNS

namespace vnetorch_test
{
    // VNetOrch programs a SAI virtual router per (non-default-scope) VNET via
    // create/set/remove with no bulk ops, so the WITH_SET generic mock variant
    // fits (same shape as sai_policer_api).
    DEFINE_SAI_GENERIC_API_MOCK_WITH_SET(virtual_router, virtual_router);

    using namespace ::testing;
    using namespace std;
    using namespace swss;
    using namespace mock_orch_test;

    // The mock harness has no populated ASIC_DB (no syncd), so -- as with the
    // other ported suites -- we verify what VNetOrch programs by capturing the
    // attributes it passes to the mocked SAI virtual-router API rather than
    // reading ASIC_DB. In the VS test this is check_vnet_entry() asserting a new
    // SAI_OBJECT_TYPE_VIRTUAL_ROUTER exists for the VNET.
    struct VirtualRouterSaiMock
    {
        int create_count = 0;
        sai_object_id_t created_oid = SAI_NULL_OBJECT_ID;
        vector<sai_attribute_t> create_attrs;
        sai_object_id_t removed_oid = SAI_NULL_OBJECT_ID;

        sai_status_t handleCreate(sai_object_id_t *vr_id, sai_object_id_t switch_id,
                                  uint32_t attr_count, const sai_attribute_t *attr_list)
        {
            create_attrs.assign(attr_list, attr_list + attr_count);
            // Call through to real libsaivs so a valid VR OID is returned. A
            // fabricated OID makes downstream real SAI calls on this VR --
            // e.g. RouteOrch::addLinkLocalRouteToMe()'s create_route_entry() --
            // fail, which throws and aborts the VNET bind before any tunnel
            // objects are programmed.
            sai_status_t status = old_sai_virtual_router_api->create_virtual_router(
                vr_id, switch_id, attr_count, attr_list);
            if (status == SAI_STATUS_SUCCESS)
            {
                created_oid = *vr_id;
                create_count++;
            }
            return status;
        }

        sai_status_t handleRemove(sai_object_id_t vr_id)
        {
            removed_oid = vr_id;
            return SAI_STATUS_SUCCESS;
        }
    };

    // Raw (list,count) attribute lookup -- the capture handlers see the C SAI
    // signature, not a vector, so mock_test_helpers::findAttr doesn't apply.
    static const sai_attribute_t *findRawAttr(const sai_attribute_t *list,
                                              uint32_t count, sai_attr_id_t id)
    {
        for (uint32_t i = 0; i < count; ++i)
        {
            if (list[i].id == id)
            {
                return &list[i];
            }
        }
        return nullptr;
    }

    static bool ipAddrEquals(const sai_ip_address_t &a, const string &ip)
    {
        swss::IpAddress expected(ip);
        return a.addr_family == SAI_IP_ADDR_FAMILY_IPV4 &&
               a.addr.ip4 == expected.getV4Addr();
    }

    // Captured VXLAN tunnel SAI objects with the attributes VNetOrch /
    // VxlanTunnelOrch program -- the mock-test equivalent of the ASIC_DB reads
    // in vnet_lib.check_vxlan_tunnel() / check_vxlan_tunnel_entry().
    struct TunnelCaptures
    {
        struct Map { sai_object_id_t oid; int32_t type; };
        struct Tunnel
        {
            sai_object_id_t oid;
            int32_t type = -1;
            sai_object_id_t underlay = SAI_NULL_OBJECT_ID;
            sai_ip_address_t src{};
            vector<sai_object_id_t> decap_mappers;
            vector<sai_object_id_t> encap_mappers;
        };
        struct Term
        {
            sai_object_id_t oid;
            int32_t type = -1;
            int32_t tunnel_type = -1;
            sai_object_id_t vr = SAI_NULL_OBJECT_ID;
            sai_object_id_t action_tunnel = SAI_NULL_OBJECT_ID;
            sai_ip_address_t dst{};
        };
        struct MapEntry
        {
            sai_object_id_t oid;
            int32_t map_type = -1;
            sai_object_id_t tunnel_map = SAI_NULL_OBJECT_ID;
            sai_object_id_t vr_key = SAI_NULL_OBJECT_ID;
            sai_object_id_t vr_value = SAI_NULL_OBJECT_ID;
            uint32_t vni_key = 0;
            uint32_t vni_value = 0;
        };
        vector<Map> maps;
        vector<Tunnel> tunnels;
        vector<Term> terms;
        vector<MapEntry> mapEntries;
        vector<sai_object_id_t> removedTunnels;
        vector<sai_object_id_t> removedMaps;
        vector<sai_object_id_t> removedTerms;
        vector<sai_object_id_t> removedMapEntries;
    };

    class VNetOrchTest : public MockOrchTest
    {
    protected:
        unique_ptr<VirtualRouterSaiMock> m_vrMock;

        // sai_tunnel_api is not routed through the mock_sai_api framework (which
        // swaps whole api structs); VxlanTunnelOrch uses the free create/remove
        // helpers, so we swap the individual function pointers to the ready-made
        // mock_sai_tunnel shims and default every call to pass through to real
        // libsaivs (so tunnel objects get valid OIDs and the map/term chain
        // succeeds) while capturing the attributes VNetOrch programs.
        NiceMock<MockSaiTunnel> m_tunnelMock;
        decltype(sai_tunnel_api->create_tunnel) m_savedCreateTunnel{};
        decltype(sai_tunnel_api->create_tunnel_map) m_savedCreateTunnelMap{};
        decltype(sai_tunnel_api->create_tunnel_map_entry) m_savedCreateTunnelMapEntry{};
        decltype(sai_tunnel_api->create_tunnel_term_table_entry) m_savedCreateTunnelTerm{};
        decltype(sai_tunnel_api->remove_tunnel) m_savedRemoveTunnel{};
        decltype(sai_tunnel_api->remove_tunnel_map) m_savedRemoveTunnelMap{};
        decltype(sai_tunnel_api->remove_tunnel_map_entry) m_savedRemoveTunnelMapEntry{};
        decltype(sai_tunnel_api->remove_tunnel_term_table_entry) m_savedRemoveTunnelTerm{};
        TunnelCaptures m_tun;

        void ApplyInitialConfigs() override
        {
            // VNetOrch/VxlanTunnelOrch depend on ports being ready, so bring the
            // default SAI ports up first (same idiom as the other suites).
            Table port_table(m_app_db.get(), APP_PORT_TABLE_NAME);
            auto ports = ut_helper::getInitialSaiPorts();
            for (const auto &it : ports)
            {
                port_table.set(it.first, it.second);
            }
            port_table.set("PortConfigDone", {{"count", to_string(ports.size())}});
            port_table.set("PortInitDone", {{}});
            gPortsOrch->addExistingData(&port_table);
            static_cast<Orch *>(gPortsOrch)->doTask();
        }

        void PostSetUp() override
        {
            INIT_SAI_API_MOCK(virtual_router);
            MockSaiApis();
            m_vrMock = make_unique<VirtualRouterSaiMock>();

            installTunnelMock();
        }

        void PreTearDown() override
        {
            restoreTunnelMock();
            m_vrMock.reset();
            RestoreSaiApis();
            DEINIT_SAI_API_MOCK(virtual_router);
        }

        void installTunnelMock()
        {
            mock_sai_tunnel = &m_tunnelMock;

            m_savedCreateTunnel = sai_tunnel_api->create_tunnel;
            m_savedCreateTunnelMap = sai_tunnel_api->create_tunnel_map;
            m_savedCreateTunnelMapEntry = sai_tunnel_api->create_tunnel_map_entry;
            m_savedCreateTunnelTerm = sai_tunnel_api->create_tunnel_term_table_entry;
            m_savedRemoveTunnel = sai_tunnel_api->remove_tunnel;
            m_savedRemoveTunnelMap = sai_tunnel_api->remove_tunnel_map;
            m_savedRemoveTunnelMapEntry = sai_tunnel_api->remove_tunnel_map_entry;
            m_savedRemoveTunnelTerm = sai_tunnel_api->remove_tunnel_term_table_entry;

            sai_tunnel_api->create_tunnel = mock_create_tunnel;
            sai_tunnel_api->create_tunnel_map = mock_create_tunnel_map;
            sai_tunnel_api->create_tunnel_map_entry = mock_create_tunnel_map_entry;
            sai_tunnel_api->create_tunnel_term_table_entry = mock_create_tunnel_term_table_entry;
            sai_tunnel_api->remove_tunnel = mock_remove_tunnel;
            sai_tunnel_api->remove_tunnel_map = mock_remove_tunnel_map;
            sai_tunnel_api->remove_tunnel_map_entry = mock_remove_tunnel_map_entry;
            sai_tunnel_api->remove_tunnel_term_table_entry = mock_remove_tunnel_term_table_entry;

            ON_CALL(m_tunnelMock, create_tunnel(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = m_savedCreateTunnel(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        TunnelCaptures::Tunnel t;
                        t.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_ATTR_TYPE)) t.type = a->value.s32;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE)) t.underlay = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_ATTR_ENCAP_SRC_IP)) t.src = a->value.ipaddr;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_ATTR_DECAP_MAPPERS))
                            t.decap_mappers.assign(a->value.objlist.list, a->value.objlist.list + a->value.objlist.count);
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_ATTR_ENCAP_MAPPERS))
                            t.encap_mappers.assign(a->value.objlist.list, a->value.objlist.list + a->value.objlist.count);
                        m_tun.tunnels.push_back(t);
                    }
                    return st;
                }));
            ON_CALL(m_tunnelMock, create_tunnel_map(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = m_savedCreateTunnelMap(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        TunnelCaptures::Map m;
                        m.oid = *id;
                        auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ATTR_TYPE);
                        m.type = a ? a->value.s32 : -1;
                        m_tun.maps.push_back(m);
                    }
                    return st;
                }));
            ON_CALL(m_tunnelMock, create_tunnel_map_entry(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = m_savedCreateTunnelMapEntry(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        TunnelCaptures::MapEntry e;
                        e.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE)) e.map_type = a->value.s32;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP)) e.tunnel_map = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY)) e.vr_key = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE)) e.vr_value = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY)) e.vni_key = a->value.u32;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE)) e.vni_value = a->value.u32;
                        m_tun.mapEntries.push_back(e);
                    }
                    return st;
                }));
            ON_CALL(m_tunnelMock, create_tunnel_term_table_entry(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = m_savedCreateTunnelTerm(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        TunnelCaptures::Term t;
                        t.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE)) t.type = a->value.s32;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE)) t.tunnel_type = a->value.s32;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID)) t.vr = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID)) t.action_tunnel = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP)) t.dst = a->value.ipaddr;
                        m_tun.terms.push_back(t);
                    }
                    return st;
                }));
            ON_CALL(m_tunnelMock, remove_tunnel(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) { m_tun.removedTunnels.push_back(id); return m_savedRemoveTunnel(id); }));
            ON_CALL(m_tunnelMock, remove_tunnel_map(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) { m_tun.removedMaps.push_back(id); return m_savedRemoveTunnelMap(id); }));
            ON_CALL(m_tunnelMock, remove_tunnel_map_entry(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) { m_tun.removedMapEntries.push_back(id); return m_savedRemoveTunnelMapEntry(id); }));
            ON_CALL(m_tunnelMock, remove_tunnel_term_table_entry(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) { m_tun.removedTerms.push_back(id); return m_savedRemoveTunnelTerm(id); }));
        }

        void restoreTunnelMock()
        {
            if (sai_tunnel_api)
            {
                sai_tunnel_api->create_tunnel = m_savedCreateTunnel;
                sai_tunnel_api->create_tunnel_map = m_savedCreateTunnelMap;
                sai_tunnel_api->create_tunnel_map_entry = m_savedCreateTunnelMapEntry;
                sai_tunnel_api->create_tunnel_term_table_entry = m_savedCreateTunnelTerm;
                sai_tunnel_api->remove_tunnel = m_savedRemoveTunnel;
                sai_tunnel_api->remove_tunnel_map = m_savedRemoveTunnelMap;
                sai_tunnel_api->remove_tunnel_map_entry = m_savedRemoveTunnelMapEntry;
                sai_tunnel_api->remove_tunnel_term_table_entry = m_savedRemoveTunnelTerm;
            }
            mock_sai_tunnel = nullptr;
        }

        // The VS test writes VXLAN_TUNNEL / VNET to CONFIG_DB and relies on
        // vxlanmgr/vrfmgr to mirror them into APP_DB (vrfmgr passes the VNET
        // fields through unchanged). The mock harness has no cfgmgr daemons, so
        // we write the APP_DB entries the daemons would have produced.
        void setVxlanTunnel(const string &name, const string &src_ip)
        {
            Table tbl(m_app_db.get(), APP_VXLAN_TUNNEL_TABLE_NAME);
            tbl.set(name, {{"src_ip", src_ip}});
            m_VxlanTunnelOrch->addExistingData(&tbl);
            static_cast<Orch *>(m_VxlanTunnelOrch)->doTask();
        }

        void setVnet(const string &name, const string &tunnel, const string &vni,
                     const string &peer_list)
        {
            Table tbl(m_app_db.get(), APP_VNET_TABLE_NAME);
            tbl.set(name, {{"vxlan_tunnel", tunnel}, {"vni", vni}, {"peer_list", peer_list}});
            m_vnetOrch->addExistingData(&tbl);
            static_cast<Orch *>(m_vnetOrch)->doTask();
        }

        // Deletes must flow through the consumer as a DEL_COMMAND: replaying an
        // addExistingData() after removing the APP_DB key would silently no-op
        // the delete handler and lose delete/refcount coverage.
        void delVnet(const string &name)
        {
            auto consumer = dynamic_cast<Consumer *>(m_vnetOrch->getExecutor(APP_VNET_TABLE_NAME));
            consumer->addToSync({{name, DEL_COMMAND, {}}});
            static_cast<Orch *>(m_vnetOrch)->doTask(*consumer);
        }

        void delVxlanTunnel(const string &name)
        {
            auto consumer = dynamic_cast<Consumer *>(m_VxlanTunnelOrch->getExecutor(APP_VXLAN_TUNNEL_TABLE_NAME));
            consumer->addToSync({{name, DEL_COMMAND, {}}});
            static_cast<Orch *>(m_VxlanTunnelOrch)->doTask(*consumer);
        }
    };

    // Minimal end-to-end check that the fixture drives VNetOrch: creating a VNET
    // that references a VXLAN tunnel programs a SAI virtual router for the VNET
    // (the mock-test equivalent of check_vnet_entry() asserting a new
    // SAI_OBJECT_TYPE_VIRTUAL_ROUTER). The VR is created with an empty attribute
    // list, so we assert on the create call itself, not on the attributes.
    TEST_F(VNetOrchTest, VnetCreateProgramsVirtualRouter)
    {
        EXPECT_CALL(*mock_sai_virtual_router_api, create_virtual_router)
            .Times(1)
            .WillOnce(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleCreate));

        setVxlanTunnel("tunnel_v4", "10.1.0.32");
        setVnet("Vnet1", "tunnel_v4", "10001", "");

        EXPECT_EQ(m_vrMock->create_count, 1);
        EXPECT_NE(m_vrMock->created_oid, SAI_NULL_OBJECT_ID);
    }

    // Binding a VNET to a VXLAN tunnel drives VxlanTunnelOrch::createVxlanTunnelMap
    // -> createTunnelHw, programming four tunnel maps, one tunnel, and one
    // tunnel-term entry with the attributes vnet_lib.check_vxlan_tunnel() asserts.
    TEST_F(VNetOrchTest, VnetBindProgramsVxlanTunnel)
    {
        EXPECT_CALL(*mock_sai_virtual_router_api, create_virtual_router)
            .Times(1)
            .WillOnce(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleCreate));

        setVxlanTunnel("tunnel_v4", "10.1.0.32");
        setVnet("Vnet1", "tunnel_v4", "10001", "");

        // Four tunnel maps, in the order VxlanTunnelOrch programs them:
        // VNI->VLAN, VLAN->VNI, VNI->VR, VR->VNI (the tunnel_map_id[0..3]
        // ordering check_vxlan_tunnel relies on).
        ASSERT_EQ(m_tun.maps.size(), 4U);
        EXPECT_EQ(m_tun.maps[0].type, SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID);
        EXPECT_EQ(m_tun.maps[1].type, SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI);
        EXPECT_EQ(m_tun.maps[2].type, SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID);
        EXPECT_EQ(m_tun.maps[3].type, SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI);

        ASSERT_EQ(m_tun.tunnels.size(), 1U);
        const auto &t = m_tun.tunnels[0];
        EXPECT_EQ(t.type, SAI_TUNNEL_TYPE_VXLAN);
        EXPECT_NE(t.underlay, SAI_NULL_OBJECT_ID);
        EXPECT_TRUE(ipAddrEquals(t.src, "10.1.0.32"));
        // DECAP mappers = {VNI->VLAN, VNI->VR}; ENCAP mappers = {VLAN->VNI, VR->VNI}.
        ASSERT_EQ(t.decap_mappers.size(), 2U);
        EXPECT_EQ(t.decap_mappers[0], m_tun.maps[0].oid);
        EXPECT_EQ(t.decap_mappers[1], m_tun.maps[2].oid);
        ASSERT_EQ(t.encap_mappers.size(), 2U);
        EXPECT_EQ(t.encap_mappers[0], m_tun.maps[1].oid);
        EXPECT_EQ(t.encap_mappers[1], m_tun.maps[3].oid);

        ASSERT_EQ(m_tun.terms.size(), 1U);
        const auto &term = m_tun.terms[0];
        EXPECT_EQ(term.type, SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP);
        EXPECT_EQ(term.tunnel_type, SAI_TUNNEL_TYPE_VXLAN);
        EXPECT_EQ(term.vr, gVirtualRouterId);
        EXPECT_EQ(term.action_tunnel, t.oid);
        EXPECT_TRUE(ipAddrEquals(term.dst, "10.1.0.32"));
    }

    // The same bind programs the two VR<->VNI tunnel-map entries carrying the
    // VNET's VNI -- the mock equivalent of vnet_lib.check_vxlan_tunnel_entry().
    TEST_F(VNetOrchTest, VnetBindProgramsTunnelMapEntries)
    {
        EXPECT_CALL(*mock_sai_virtual_router_api, create_virtual_router)
            .Times(1)
            .WillOnce(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleCreate));

        setVxlanTunnel("tunnel_v4", "10.1.0.32");
        setVnet("Vnet1", "tunnel_v4", "10001", "");

        const sai_object_id_t vnetVr = m_vrMock->created_oid;
        ASSERT_EQ(m_tun.maps.size(), 4U);
        ASSERT_EQ(m_tun.mapEntries.size(), 2U);

        // Entry 0: VR->VNI, keyed by the VNET VR, valued with the VNI.
        const auto &e0 = m_tun.mapEntries[0];
        EXPECT_EQ(e0.map_type, SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI);
        EXPECT_EQ(e0.tunnel_map, m_tun.maps[3].oid);
        EXPECT_EQ(e0.vr_key, vnetVr);
        EXPECT_EQ(e0.vni_value, 10001U);

        // Entry 1: VNI->VR, keyed by the VNI, valued with the VNET VR.
        const auto &e1 = m_tun.mapEntries[1];
        EXPECT_EQ(e1.map_type, SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID);
        EXPECT_EQ(e1.tunnel_map, m_tun.maps[2].oid);
        EXPECT_EQ(e1.vni_key, 10001U);
        EXPECT_EQ(e1.vr_value, vnetVr);
    }

    // Deleting the VNET tears down its per-VNET SAI objects -- the two tunnel-map
    // entries and the VNET virtual router. Deleting the VXLAN tunnel then removes
    // the shared tunnel, four maps, and term entry (the mock equivalent of
    // vnet_lib.check_del_vxlan_tunnel(); the VS test's check_del_vnet_entry is a
    // no-op, so the VR/map-entry removal here is stronger than the VS coverage).
    TEST_F(VNetOrchTest, VnetAndTunnelDeleteRemoveObjects)
    {
        EXPECT_CALL(*mock_sai_virtual_router_api, create_virtual_router)
            .Times(1)
            .WillOnce(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleCreate));
        EXPECT_CALL(*mock_sai_virtual_router_api, remove_virtual_router)
            .Times(1)
            .WillOnce(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleRemove));

        setVxlanTunnel("tunnel_v4", "10.1.0.32");
        setVnet("Vnet1", "tunnel_v4", "10001", "");
        const sai_object_id_t vnetVr = m_vrMock->created_oid;
        ASSERT_EQ(m_tun.mapEntries.size(), 2U);

        delVnet("Vnet1");
        EXPECT_EQ(m_vrMock->removed_oid, vnetVr);
        EXPECT_EQ(m_tun.removedMapEntries.size(), 2U);

        delVxlanTunnel("tunnel_v4");
        EXPECT_EQ(m_tun.removedTunnels.size(), 1U);
        EXPECT_EQ(m_tun.removedMaps.size(), 4U);
        EXPECT_EQ(m_tun.removedTerms.size(), 1U);
    }
}
