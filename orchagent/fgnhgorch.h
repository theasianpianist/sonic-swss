#ifndef SWSS_FGNHGORCH_H
#define SWSS_FGNHGORCH_H

#include "orch.h"
#include "observer.h"
#include "intfsorch.h"
#include "neighorch.h"
#include "producerstatetable.h"

#include "ipaddress.h"
#include "ipaddresses.h"
#include "ipprefix.h"
#include "nexthopgroupkey.h"

#include <map>

typedef uint32_t Bank;
typedef std::set<NextHopKey> ActiveNextHops;
typedef std::vector<sai_object_id_t> FGNextHopGroupMembers;
typedef std::vector<uint32_t> HashBuckets;
typedef std::map<NextHopKey, HashBuckets> FGNextHopGroupMap;
typedef std::vector<FGNextHopGroupMap> BankFGNextHopGroupMap;
typedef std::map<Bank,Bank> InactiveBankMapsToBank;

struct FGNextHopGroupEntry
{
    sai_object_id_t         next_hop_group_id;      // next hop group id
    FGNextHopGroupMembers   nhopgroup_members;      // sai_object_ids of nexthopgroup members(0 - real_bucket_size - 1)
    ActiveNextHops          active_nexthops;        // The set of nexthops(ip+alias)
    BankFGNextHopGroupMap   syncd_fgnhg_map;        // Map of (bank) -> (nexthops) -> (index in nhopgroup_members)
    NextHopGroupKey         nhg_key;                // Full next hop group key
    InactiveBankMapsToBank  inactive_to_active_map; // Maps an inactive bank to an active one in terms of hash bkts
};

/*TODO: can we make an optimization here when we get multiple routes pointing to a fgnhg */
typedef std::map<IpPrefix, FGNextHopGroupEntry> FGRouteTable;
/* RouteTables: vrf_id, FGRouteTable */
typedef std::map<sai_object_id_t, FGRouteTable> FGRouteTables;
/* Name of the FG NHG group */
typedef std::string FgNhg;
/* Map from IP to Bank */
typedef std::map<IpAddress, Bank> NextHops;
/* Cache currently ongoing FG_NHG PREFIX additions/deletions */
typedef std::map<IpPrefix, NextHopGroupKey> FgPrefixOpCache;

/* Store the indices occupied by a bank */
typedef struct
{
    uint32_t start_index;
    uint32_t end_index;
} BankIndexRange;

typedef struct FgNhgEntry
{
    string fg_nhg_name;                                  // Name of FG NHG group configured by user
    uint32_t configured_bucket_size;                    // Bucket size configured by user
    uint32_t real_bucket_size;                          // Real bucket size as queried from SAI
    NextHops next_hops;                                  // The IP to Bank mapping configured by user
    std::vector<IpPrefix> prefixes;                     // Prefix which desires FG behavior
    std::vector<BankIndexRange> hash_bucket_indices;  // The hash bucket indices for a bank
} FgNhgEntry;

/* Map from IP prefix to user configured FG NHG entries */
typedef std::map<IpPrefix, FgNhgEntry*> FgNhgPrefixes; 
/* Main structure to hold user configuration */
typedef std::map<FgNhg, FgNhgEntry> FgNhgs;

/* Helper struct populated at every route change to identify the next-hop changes which occured */
typedef struct
{
    std::vector<NextHopKey> nhs_to_del;
    std::vector<NextHopKey> nhs_to_add;
    std::vector<NextHopKey> active_nhs;
} BankMemberChanges;

class FgNhgOrch : public Orch
{
public:
    FgNhgPrefixes fgNhgPrefixes;
    FgNhgOrch(DBConnector *db, DBConnector *appDb, DBConnector *stateDb, vector<string> &tableNames, NeighOrch *neighOrch, IntfsOrch *intfsOrch, VRFOrch *vrfOrch);

    bool addRoute(sai_object_id_t, const IpPrefix&, const NextHopGroupKey&);
    bool removeRoute(sai_object_id_t, const IpPrefix&);
    bool validNextHopInNextHopGroup(const NextHopKey&);
    bool invalidNextHopInNextHopGroup(const NextHopKey&);

private:
    NeighOrch *m_neighOrch;
    IntfsOrch *m_intfsOrch;
    VRFOrch *m_vrfOrch;
    FgNhgs m_FgNhgs;
    FGRouteTables m_syncdFGRouteTables;
    Table m_stateWarmRestartRouteTable;
    ProducerStateTable m_routeTable;
    FgPrefixOpCache m_fgPrefixAddCache;
    FgPrefixOpCache m_fgPrefixDelCache;

    bool setNewNhgMembers(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    std::vector<BankMemberChanges> &bank_member_changes, 
                    std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix&);
    bool computeAndSetHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry,
                    FgNhgEntry *fgNhgEntry, std::vector<BankMemberChanges> &bank_member_changes,
                    std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix&);
    bool setActiveBankHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    uint32_t bank, uint32_t syncd_bank, std::vector<BankMemberChanges> bank_member_changes,
                    std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix&);
    bool setInactiveBankHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    uint32_t bank,std::vector<BankMemberChanges> &bank_member_changes,
                    std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix&);
    bool setInactiveBankToNextAvailableActiveBank(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    uint32_t bank, std::vector<BankMemberChanges> bank_member_changes,
                    std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix&);
    void calculateBankHashBucketStartIndices(FgNhgEntry *fgNhgEntry);
    void setStateDbRouteEntry(const IpPrefix&, uint32_t index, NextHopKey nextHop);
    bool writeHashBucketChange(FGNextHopGroupEntry *syncd_fg_route_entry, uint32_t index, sai_object_id_t nh_oid,
                    const IpPrefix &ipPrefix, NextHopKey nextHop);
    bool createFineGrainedNextHopGroup(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    const NextHopGroupKey &nextHops);
    bool removeFineGrainedNextHopGroup(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry);
    bool createFineGrainedRouteEntry(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
                    sai_object_id_t vrf_id, const IpPrefix &ipPrefix, const NextHopGroupKey &nextHops);

    vector<FieldValueTuple> generateRouteTableFromNhgKey(NextHopGroupKey nhg);
    bool doTaskFgNhg(const KeyOpFieldsValuesTuple&);
    bool doTaskFgNhgPrefix(const KeyOpFieldsValuesTuple&);
    bool doTaskFgNhgMember(const KeyOpFieldsValuesTuple&);
    void doTask(Consumer& consumer);
};

#endif /* SWSS_FGNHGORCH_H */
