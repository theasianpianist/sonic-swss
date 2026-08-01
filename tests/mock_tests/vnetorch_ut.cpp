#include "ut_helper.h"
#include "mock_orchagent_main.h"
#include "mock_sai_api.h"
#include "mock_sai_tunnel.h"
#include "mock_orch_test.h"
#include "common/mock_test_helpers.h"
#include "mock_table.h"
#include "macaddress.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <set>

EXTERN_MOCK_FNS

namespace vnetorch_test
{
    // VNetOrch programs a SAI virtual router per (non-default-scope) VNET via
    // create/set/remove with no bulk ops, so the WITH_SET generic mock variant
    // fits (same shape as sai_policer_api).
    DEFINE_SAI_GENERIC_API_MOCK_WITH_SET(virtual_router, virtual_router);
    // VNetRouteOrch programs tunnel routes with non-bulk single-object SAI
    // calls, so the plain generic mocks fit (next hop, next hop group + members,
    // and the route entry). All default to call-through to real libsaivs so the
    // route -> next hop -> tunnel object references resolve to valid OIDs.
    DEFINE_SAI_GENERIC_API_MOCK(next_hop, next_hop);
    DEFINE_SAI_GENERIC_APIS_MOCK(next_hop_group, next_hop_group, next_hop_group_member);
    DEFINE_SAI_API_MOCK_MATCH_ENTRY(route);

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

    static bool saiMacEquals(const sai_mac_t &m, const string &mac)
    {
        swss::MacAddress expected(mac);
        return memcmp(m, expected.getMac(), sizeof(sai_mac_t)) == 0;
    }

    static bool prefixAddrEquals(const sai_ip_prefix_t &p, const string &ip)
    {
        swss::IpAddress expected(ip);
        return p.addr_family == SAI_IP_ADDR_FAMILY_IPV4 &&
               p.addr.ip4 == expected.getV4Addr();
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

    // Captured SAI next-hop / next-hop-group / route objects VNetRouteOrch
    // programs for a VNET tunnel route -- the mock-test equivalent of the
    // ASIC_DB reads in vnet_lib.check_vnet_routes() / check_vnet_ecmp_routes().
    struct RouteCaptures
    {
        struct NextHop
        {
            sai_object_id_t oid = SAI_NULL_OBJECT_ID;
            int32_t type = -1;
            sai_ip_address_t ip{};
            sai_object_id_t tunnel_id = SAI_NULL_OBJECT_ID;
            bool has_vni = false;
            uint32_t vni = 0;
            bool has_mac = false;
            sai_mac_t mac{};
        };
        struct Group { sai_object_id_t oid = SAI_NULL_OBJECT_ID; int32_t type = -1; };
        struct Member
        {
            sai_object_id_t oid = SAI_NULL_OBJECT_ID;
            sai_object_id_t nhg = SAI_NULL_OBJECT_ID;
            sai_object_id_t nh = SAI_NULL_OBJECT_ID;
            bool has_seq = false;
            uint32_t seq = 0;
        };
        struct Route
        {
            sai_object_id_t vr = SAI_NULL_OBJECT_ID;
            sai_ip_prefix_t dest{};
            sai_object_id_t next_hop_id = SAI_NULL_OBJECT_ID;
        };
        vector<NextHop> nexthops;
        vector<Group> groups;
        vector<Member> members;
        vector<Route> routes;
        vector<sai_object_id_t> removedNexthops;
        vector<sai_object_id_t> removedGroups;
        vector<sai_object_id_t> removedMembers;
        vector<sai_ip_prefix_t> removedRoutes;
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

        unique_ptr<VNetRouteOrch> m_vnetRouteOrch;
        RouteCaptures m_rt;

        void SetUp() override
        {
            // gDB (the mock DB backing swss::Table) is process-global and is not
            // flushed by MockOrchTest::TearDown(), so CONFIG/APP rows a test
            // writes (VNET, VXLAN_TUNNEL, VNET_ROUTE_TUNNEL...) would linger and
            // be re-consumed by the next test's addExistingData()+doTask(),
            // inflating the captured SAI object counts. Reset before each test.
            testing_db::reset();
            MockOrchTest::SetUp();
        }

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
            INIT_SAI_API_MOCK(next_hop);
            INIT_SAI_API_MOCK(next_hop_group);
            INIT_SAI_API_MOCK(route);
            MockSaiApis();
            m_vrMock = make_unique<VirtualRouterSaiMock>();
            // Record every virtual-router create (the VNET's, plus any the route
            // path drives) so created_oid always reflects the latest VR. Route
            // tests capture the VNET's VR right after setVnet(), before any other.
            ON_CALL(*mock_sai_virtual_router_api, create_virtual_router)
                .WillByDefault(Invoke(m_vrMock.get(), &VirtualRouterSaiMock::handleCreate));

            installTunnelMock();
            installRouteMock();

            // VNetRouteOrch's ctor calls gBfdOrch->attach(this) with no null
            // guard, so gBfdOrch must exist first. VNetRouteOrch has no dtor of
            // its own (never detaches), so gBfdOrch must outlive it -- see
            // PreTearDown for the matching teardown order.
            TableConnector stateDbBfdSessionTable(m_state_db.get(), STATE_BFD_SESSION_TABLE_NAME);
            gBfdOrch = new BfdOrch(m_app_db.get(), APP_BFD_SESSION_TABLE_NAME, stateDbBfdSessionTable);

            // VNetRouteOrch::postRouteState() dereferences gTunneldecapOrch
            // (getSubnetDecapConfig()) on every tunnel route, so it must exist
            // before any route task runs. Subnet decap is disabled by default,
            // so no decap term is programmed -- it just needs to be non-null.
            vector<string> tunnel_tables = {
                APP_TUNNEL_DECAP_TABLE_NAME, APP_TUNNEL_DECAP_TERM_TABLE_NAME};
            gTunneldecapOrch = new TunnelDecapOrch(
                m_app_db.get(), m_state_db.get(), m_config_db.get(), tunnel_tables);

            // Drive VNetRouteOrch directly off the APP_DB VNET_ROUTE(_TUNNEL)
            // tables, standing in for VNetCfgRouteOrch's CONFIG->APP translation
            // (the same tables orchdaemon wires it to).
            vector<string> vnet_route_tables = {
                APP_VNET_RT_TABLE_NAME, APP_VNET_RT_TUNNEL_TABLE_NAME};
            m_vnetRouteOrch = make_unique<VNetRouteOrch>(
                m_app_db.get(), vnet_route_tables, m_vnetOrch);
        }

        void PreTearDown() override
        {
            // Tear the route orch down before gBfdOrch: it attached to gBfdOrch
            // in its ctor and relies on gBfdOrch staying alive until it is gone.
            m_vnetRouteOrch.reset();
            delete gBfdOrch;
            gBfdOrch = nullptr;
            delete gTunneldecapOrch;
            gTunneldecapOrch = nullptr;

            restoreTunnelMock();
            m_vrMock.reset();
            RestoreSaiApis();
            DEINIT_SAI_API_MOCK(virtual_router);
            DEINIT_SAI_API_MOCK(next_hop);
            DEINIT_SAI_API_MOCK(next_hop_group);
            DEINIT_SAI_API_MOCK(route);
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

        // Capture the SAI next-hop / next-hop-group / route objects
        // VNetRouteOrch programs, calling through to real libsaivs so downstream
        // references (route -> next hop -> tunnel) resolve to valid OIDs.
        // VNetRouteOrch uses the non-bulk single-object create calls.
        void installRouteMock()
        {
            ON_CALL(*mock_sai_next_hop_api, create_next_hop(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = old_sai_next_hop_api->create_next_hop(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        RouteCaptures::NextHop nh;
                        nh.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_ATTR_TYPE)) nh.type = a->value.s32;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_ATTR_IP)) nh.ip = a->value.ipaddr;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_ATTR_TUNNEL_ID)) nh.tunnel_id = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_ATTR_TUNNEL_VNI)) { nh.has_vni = true; nh.vni = a->value.u32; }
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_ATTR_TUNNEL_MAC))
                        {
                            nh.has_mac = true;
                            memcpy(nh.mac, a->value.mac, sizeof(sai_mac_t));
                        }
                        m_rt.nexthops.push_back(nh);
                    }
                    return st;
                }));
            ON_CALL(*mock_sai_next_hop_api, remove_next_hop(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) {
                    m_rt.removedNexthops.push_back(id);
                    return old_sai_next_hop_api->remove_next_hop(id);
                }));

            ON_CALL(*mock_sai_next_hop_group_api, create_next_hop_group(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = old_sai_next_hop_group_api->create_next_hop_group(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        RouteCaptures::Group g;
                        g.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_GROUP_ATTR_TYPE)) g.type = a->value.s32;
                        m_rt.groups.push_back(g);
                    }
                    return st;
                }));
            ON_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) {
                    m_rt.removedGroups.push_back(id);
                    return old_sai_next_hop_group_api->remove_next_hop_group(id);
                }));
            ON_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member(_, _, _, _))
                .WillByDefault(Invoke([this](sai_object_id_t *id, sai_object_id_t sw,
                                             uint32_t n, const sai_attribute_t *l) {
                    sai_status_t st = old_sai_next_hop_group_api->create_next_hop_group_member(id, sw, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        RouteCaptures::Member m;
                        m.oid = *id;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID)) m.nhg = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID)) m.nh = a->value.oid;
                        if (auto a = findRawAttr(l, n, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_SEQUENCE_ID)) { m.has_seq = true; m.seq = a->value.u32; }
                        m_rt.members.push_back(m);
                    }
                    return st;
                }));
            ON_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member(_))
                .WillByDefault(Invoke([this](sai_object_id_t id) {
                    m_rt.removedMembers.push_back(id);
                    return old_sai_next_hop_group_api->remove_next_hop_group_member(id);
                }));

            ON_CALL(*mock_sai_route_api, create_route_entry(_, _, _))
                .WillByDefault(Invoke([this](const sai_route_entry_t *e, uint32_t n,
                                             const sai_attribute_t *l) {
                    sai_status_t st = old_sai_route_api->create_route_entry(e, n, l);
                    if (st == SAI_STATUS_SUCCESS)
                    {
                        RouteCaptures::Route r;
                        r.vr = e->vr_id;
                        r.dest = e->destination;
                        if (auto a = findRawAttr(l, n, SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)) r.next_hop_id = a->value.oid;
                        m_rt.routes.push_back(r);
                    }
                    return st;
                }));
            ON_CALL(*mock_sai_route_api, remove_route_entry(_))
                .WillByDefault(Invoke([this](const sai_route_entry_t *e) {
                    m_rt.removedRoutes.push_back(e->destination);
                    return old_sai_route_api->remove_route_entry(e);
                }));
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

        // The VS test writes CONFIG_DB VNET_ROUTE_TUNNEL and relies on
        // VNetCfgRouteOrch to mirror it to APP_DB VNET_ROUTE_TUNNEL_TABLE. The
        // mock harness has no VNetCfgRouteOrch, so we write the APP_DB entry it
        // would have produced (key "vnet:prefix", the ':' separator
        // VNetRouteRequest uses). endpoint is a comma-separated list -> a single
        // endpoint programs one tunnel next hop; multiple endpoints program an
        // ECMP next hop group.
        void setVnetRoute(const string &vnet, const string &prefix,
                          const string &endpoints, const string &mac = "",
                          const string &vni = "")
        {
            vector<FieldValueTuple> fvs = {{"endpoint", endpoints}};
            if (!mac.empty()) fvs.push_back({"mac_address", mac});
            if (!vni.empty()) fvs.push_back({"vni", vni});
            Table tbl(m_app_db.get(), APP_VNET_RT_TUNNEL_TABLE_NAME);
            tbl.set(vnet + ":" + prefix, fvs);
            m_vnetRouteOrch->addExistingData(&tbl);
            static_cast<Orch *>(m_vnetRouteOrch.get())->doTask();
        }

        void delVnetRoute(const string &vnet, const string &prefix)
        {
            auto consumer = dynamic_cast<Consumer *>(
                m_vnetRouteOrch->getExecutor(APP_VNET_RT_TUNNEL_TABLE_NAME));
            consumer->addToSync({{vnet + ":" + prefix, DEL_COMMAND, {}}});
            static_cast<Orch *>(m_vnetRouteOrch.get())->doTask(*consumer);
        }

        // Find the captured route for an IPv4 prefix, skipping the VNET's IPv6
        // link-local route that RouteOrch programs during bind.
        const RouteCaptures::Route *findRoute(const string &ip) const
        {
            for (const auto &r : m_rt.routes)
            {
                if (prefixAddrEquals(r.dest, ip))
                {
                    return &r;
                }
            }
            return nullptr;
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

    // A single-endpoint VNET tunnel route programs one SAI tunnel encap next hop
    // (TUNNEL_ENCAP over the VNET's tunnel to the endpoint) and one route entry
    // in the VNET's virtual router pointing straight at it -- the mock
    // equivalent of vnet_lib.check_vnet_routes() with a single endpoint.
    TEST_F(VNetOrchTest, VnetRouteProgramsTunnelNextHop)
    {
        setVxlanTunnel("tunnel_v4", "10.10.10.10");
        setVnet("Vnet_2000", "tunnel_v4", "2000", "");
        const sai_object_id_t vnetVr = m_vrMock->created_oid;

        setVnetRoute("Vnet_2000", "100.100.1.1/32", "10.10.10.1");

        // One tunnel encap next hop to the endpoint, over the VNET's tunnel.
        ASSERT_EQ(m_rt.nexthops.size(), 1U);
        const auto &nh = m_rt.nexthops[0];
        EXPECT_EQ(nh.type, SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP);
        EXPECT_TRUE(ipAddrEquals(nh.ip, "10.10.10.1"));
        ASSERT_EQ(m_tun.tunnels.size(), 1U);
        EXPECT_EQ(nh.tunnel_id, m_tun.tunnels[0].oid);
        EXPECT_FALSE(nh.has_vni);
        EXPECT_FALSE(nh.has_mac);

        // Single endpoint -> no next hop group; the route points at the next hop.
        EXPECT_TRUE(m_rt.groups.empty());

        const RouteCaptures::Route *r = findRoute("100.100.1.1");
        ASSERT_NE(r, nullptr);
        EXPECT_EQ(r->vr, vnetVr);
        EXPECT_EQ(r->next_hop_id, nh.oid);
    }

    // A route whose endpoint carries an inner MAC programs the tunnel next hop
    // with SAI_NEXT_HOP_ATTR_TUNNEL_MAC -- vnet_lib.check_vnet_routes(..., mac).
    TEST_F(VNetOrchTest, VnetRouteWithMacProgramsTunnelMac)
    {
        setVxlanTunnel("tunnel_v4", "10.10.10.10");
        setVnet("Vnet_2000", "tunnel_v4", "2000", "");

        setVnetRoute("Vnet_2000", "100.100.2.1/32", "10.10.10.2", "00:12:34:56:78:9A");

        ASSERT_EQ(m_rt.nexthops.size(), 1U);
        const auto &nh = m_rt.nexthops[0];
        EXPECT_EQ(nh.type, SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP);
        EXPECT_TRUE(ipAddrEquals(nh.ip, "10.10.10.2"));
        ASSERT_TRUE(nh.has_mac);
        EXPECT_TRUE(saiMacEquals(nh.mac, "00:12:34:56:78:9A"));
    }

    // A multi-endpoint route programs one tunnel encap next hop per endpoint, a
    // next hop group binding them, and a route entry pointing at the group --
    // the mock equivalent of vnet_lib.check_vnet_ecmp_routes().
    TEST_F(VNetOrchTest, VnetEcmpRouteProgramsNextHopGroup)
    {
        setVxlanTunnel("tunnel_v4", "7.7.7.7");
        setVnet("Vnet1", "tunnel_v4", "10007", "");
        const sai_object_id_t vnetVr = m_vrMock->created_oid;

        setVnetRoute("Vnet1", "100.100.1.1/32", "7.0.0.1,7.0.0.2,7.0.0.3");

        // One tunnel encap next hop per endpoint, all over the VNET's tunnel.
        ASSERT_EQ(m_rt.nexthops.size(), 3U);
        ASSERT_EQ(m_tun.tunnels.size(), 1U);
        for (const auto &nh : m_rt.nexthops)
        {
            EXPECT_EQ(nh.type, SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP);
            EXPECT_EQ(nh.tunnel_id, m_tun.tunnels[0].oid);
        }
        for (const char *ep : {"7.0.0.1", "7.0.0.2", "7.0.0.3"})
        {
            bool found = false;
            for (const auto &nh : m_rt.nexthops)
            {
                if (ipAddrEquals(nh.ip, ep)) found = true;
            }
            EXPECT_TRUE(found) << "missing tunnel next hop for endpoint " << ep;
        }

        // One next hop group. Orchagent programs SAI_NEXT_HOP_GROUP_TYPE_ECMP,
        // which is the same enum value libsairedis serializes to the
        // ..._DYNAMIC_UNORDERED_ECMP string the VS test matches.
        ASSERT_EQ(m_rt.groups.size(), 1U);
        const sai_object_id_t nhg = m_rt.groups[0].oid;
        EXPECT_EQ(m_rt.groups[0].type, SAI_NEXT_HOP_GROUP_TYPE_ECMP);

        // One member per endpoint, all bound to the group, each referencing a
        // captured tunnel next hop.
        ASSERT_EQ(m_rt.members.size(), 3U);
        set<sai_object_id_t> nhOids;
        for (const auto &nh : m_rt.nexthops) nhOids.insert(nh.oid);
        for (const auto &m : m_rt.members)
        {
            EXPECT_EQ(m.nhg, nhg);
            EXPECT_EQ(nhOids.count(m.nh), 1U);
        }

        // The route points at the group, in the VNET's virtual router.
        const RouteCaptures::Route *r = findRoute("100.100.1.1");
        ASSERT_NE(r, nullptr);
        EXPECT_EQ(r->vr, vnetVr);
        EXPECT_EQ(r->next_hop_id, nhg);
    }

    // Deleting a single-endpoint route removes its route entry and the tunnel
    // next hop (vnet_lib.check_del_vnet_routes()). The delete flows through the
    // consumer as a DEL_COMMAND so the delete handler actually runs.
    TEST_F(VNetOrchTest, VnetRouteDeleteRemovesObjects)
    {
        setVxlanTunnel("tunnel_v4", "10.10.10.10");
        setVnet("Vnet_2000", "tunnel_v4", "2000", "");
        setVnetRoute("Vnet_2000", "100.100.1.1/32", "10.10.10.1");
        ASSERT_EQ(m_rt.nexthops.size(), 1U);
        const sai_object_id_t nhOid = m_rt.nexthops[0].oid;

        delVnetRoute("Vnet_2000", "100.100.1.1/32");

        bool routeRemoved = false;
        for (const auto &d : m_rt.removedRoutes)
        {
            if (prefixAddrEquals(d, "100.100.1.1")) routeRemoved = true;
        }
        EXPECT_TRUE(routeRemoved);
        EXPECT_NE(find(m_rt.removedNexthops.begin(), m_rt.removedNexthops.end(), nhOid),
                  m_rt.removedNexthops.end());
    }
}
