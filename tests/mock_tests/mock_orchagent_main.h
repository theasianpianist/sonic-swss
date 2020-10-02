#pragma once

#include "orch.h"
#include "switchorch.h"
#include "crmorch.h"
#include "portsorch.h"
#include "routeorch.h"
#include "intfsorch.h"
#include "neighorch.h"
#include "fdborch.h"
#include "mirrororch.h"
#include "bufferorch.h"
#include "vrforch.h"
#include "vnetorch.h"
#include "vxlanorch.h"
#include "policerorch.h"

extern int gBatchSize;
extern bool gSwssRecord;
extern bool gSairedisRecord;
extern bool gLogRotate;
extern bool gSaiRedisLogRotate;
extern ofstream gRecordOfs;
extern string gRecordFile;

extern MacAddress gMacAddress;
extern MacAddress gVxlanMacAddress;

extern sai_object_id_t gSwitchId;
extern sai_object_id_t gVirtualRouterId;
extern sai_object_id_t gUnderlayIfId;

extern SwitchOrch *gSwitchOrch;
extern CrmOrch *gCrmOrch;
extern PortsOrch *gPortsOrch;
extern RouteOrch *gRouteOrch;
extern IntfsOrch *gIntfsOrch;
extern NeighOrch *gNeighOrch;
extern FdbOrch *gFdbOrch;
extern MirrorOrch *gMirrorOrch;
extern BufferOrch *gBufferOrch;
extern VRFOrch *gVrfOrch;

extern sai_acl_api_t *sai_acl_api;
extern sai_switch_api_t *sai_switch_api;
extern sai_virtual_router_api_t *sai_virtual_router_api;
extern sai_port_api_t *sai_port_api;
extern sai_lag_api_t *sai_lag_api;
extern sai_vlan_api_t *sai_vlan_api;
extern sai_bridge_api_t *sai_bridge_api;
extern sai_router_interface_api_t *sai_router_intfs_api;
extern sai_route_api_t *sai_route_api;
extern sai_neighbor_api_t *sai_neighbor_api;
extern sai_tunnel_api_t *sai_tunnel_api;
extern sai_next_hop_api_t *sai_next_hop_api;
extern sai_hostif_api_t *sai_hostif_api;
extern sai_buffer_api_t *sai_buffer_api;
extern sai_queue_api_t *sai_queue_api;
