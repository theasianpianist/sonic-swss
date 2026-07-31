#include "ut_helper.h"
#include "mock_orchagent_main.h"
#include "mock_sai_api.h"
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

    static constexpr sai_object_id_t kVnetVrOid = 0x3000000000a01;

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

        sai_status_t handleCreate(sai_object_id_t *vr_id, sai_object_id_t,
                                  uint32_t attr_count, const sai_attribute_t *attr_list)
        {
            *vr_id = kVnetVrOid;
            created_oid = kVnetVrOid;
            create_count++;
            create_attrs.assign(attr_list, attr_list + attr_count);
            return SAI_STATUS_SUCCESS;
        }

        sai_status_t handleRemove(sai_object_id_t vr_id)
        {
            removed_oid = vr_id;
            return SAI_STATUS_SUCCESS;
        }
    };

    class VNetOrchTest : public MockOrchTest
    {
    protected:
        unique_ptr<VirtualRouterSaiMock> m_vrMock;

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
        }

        void PreTearDown() override
        {
            m_vrMock.reset();
            RestoreSaiApis();
            DEINIT_SAI_API_MOCK(virtual_router);
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
        EXPECT_EQ(m_vrMock->created_oid, kVnetVrOid);
    }
}
