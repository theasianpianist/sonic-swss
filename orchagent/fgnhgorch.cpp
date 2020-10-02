#include <assert.h>
#include <inttypes.h>
#include "fgnhgorch.h"
#include "routeorch.h"
#include "logger.h"
#include "swssnet.h"
#include "crmorch.h"
#include <array>

extern sai_object_id_t gVirtualRouterId;
extern sai_object_id_t gSwitchId;

extern sai_next_hop_group_api_t*    sai_next_hop_group_api;
extern sai_route_api_t*             sai_route_api;

extern RouteOrch *gRouteOrch;
extern CrmOrch *gCrmOrch;

FgNhgOrch::FgNhgOrch(DBConnector *db, DBConnector *appDb, DBConnector *stateDb, vector<string> &tableNames, NeighOrch *neighOrch, IntfsOrch *intfsOrch, VRFOrch *vrfOrch) :
        Orch(db, tableNames),
        m_neighOrch(neighOrch),
        m_intfsOrch(intfsOrch),
        m_vrfOrch(vrfOrch),
        m_stateWarmRestartRouteTable(stateDb, STATE_FG_ROUTE_TABLE_NAME),
        m_routeTable(appDb, APP_ROUTE_TABLE_NAME)
{
     SWSS_LOG_ENTER();
}


/* calculateBankHashBucketStartIndices: generates the hash_bucket_indices for all banks
 * and stores it in fgNhgEntry for the group. 
 * The function will identify the # of next-hops assigned to each bank and 
 * assign the total number of hash buckets for a bank, based on the proportional
 * number of next-hops in the bank. 
 * eg: Bank0: 6 nh, Bank1: 3 nh, total buckets: 30 => 
 *      calculateBankHashBucketStartIndices: Bank0: Bucket# 0-19, Bank1: Bucket# 20-29
 */
void FgNhgOrch::calculateBankHashBucketStartIndices(FgNhgEntry *fgNhgEntry)
{
    SWSS_LOG_ENTER();
    uint32_t num_banks = 0;
    vector<uint32_t> memb_per_bank;
    for (auto nh : fgNhgEntry->next_hops)
    {
        while (nh.second + 1 > num_banks)
        {
            num_banks++;
            memb_per_bank.push_back(0);
        }
        memb_per_bank[nh.second] = memb_per_bank[nh.second] + 1;
    }

    uint32_t buckets_per_nexthop = fgNhgEntry->real_bucket_size/((uint32_t)fgNhgEntry->next_hops.size());
    uint32_t extra_buckets = fgNhgEntry->real_bucket_size - (buckets_per_nexthop*((uint32_t)fgNhgEntry->next_hops.size()));
    uint32_t split_extra_buckets_among_bank = extra_buckets/num_banks;
    extra_buckets = extra_buckets - (split_extra_buckets_among_bank*num_banks);

    uint32_t prev_idx = 0;

    for (uint32_t i = 0; i < memb_per_bank.size(); i++)
    {
        BankIndexRange bir;
        bir.start_index = prev_idx;
        bir.end_index = bir.start_index + (buckets_per_nexthop * memb_per_bank[i]) + split_extra_buckets_among_bank - 1;
        if (extra_buckets > 0)
        {
            bir.end_index = bir.end_index + 1;
            extra_buckets--;
        }
        if (i == fgNhgEntry->hash_bucket_indices.size())
        {
            fgNhgEntry->hash_bucket_indices.push_back(bir);
        }
        else
        {
            fgNhgEntry->hash_bucket_indices[i] = bir;
        }
        prev_idx = bir.end_index + 1;
        SWSS_LOG_INFO("Calculate_bank_hash_bucket_start_indices: bank %d, si %d, ei %d",
                       i, fgNhgEntry->hash_bucket_indices[i].start_index, fgNhgEntry->hash_bucket_indices[i].end_index);
    }
}


void FgNhgOrch::setStateDbRouteEntry(const IpPrefix &ipPrefix, uint32_t index, NextHopKey nextHop)
{
    SWSS_LOG_ENTER();

    string key = ipPrefix.to_string();
    // Write to StateDb
    std::vector<FieldValueTuple> fvs;

    // check if profile already exists - if yes - skip creation
    m_stateWarmRestartRouteTable.get(key, fvs);

    //bucket rewrite
    if (fvs.size() > index)
    {
        FieldValueTuple fv(std::to_string(index), nextHop.to_string());
        fvs[index] = fv;
        SWSS_LOG_INFO("Set state db entry for ip prefix %s next hop %s with index %d",
                        ipPrefix.to_string().c_str(), nextHop.to_string().c_str(), index);
        m_stateWarmRestartRouteTable.set(key, fvs);
    }
    else
    {
        fvs.push_back(FieldValueTuple(std::to_string(index), nextHop.to_string()));
        SWSS_LOG_INFO("Add new next hop entry %s with index %d for ip prefix %s",
                nextHop.to_string().c_str(), index, ipPrefix.to_string().c_str());
        m_stateWarmRestartRouteTable.set(key, fvs);
    }

}


bool FgNhgOrch::writeHashBucketChange(FGNextHopGroupEntry *syncd_fg_route_entry, uint32_t index, sai_object_id_t nh_oid,
        const IpPrefix &ipPrefix, NextHopKey nextHop)
{
    SWSS_LOG_ENTER();

    sai_attribute_t nhgm_attr;
    nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
    nhgm_attr.value.oid = nh_oid;
    sai_status_t status = sai_next_hop_group_api->set_next_hop_group_member_attribute(
                                                              syncd_fg_route_entry->nhopgroup_members[index],
                                                              &nhgm_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to set next hop oid %" PRIx64 " member %" PRIx64 ": %d",
            syncd_fg_route_entry->nhopgroup_members[index], nh_oid, status);
        return false;
    }

    setStateDbRouteEntry(ipPrefix, index, nextHop);
    return true;
}


bool FgNhgOrch::createFineGrainedNextHopGroup(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
        const NextHopGroupKey &nextHops)
{
    SWSS_LOG_ENTER();
    string platform = getenv("platform") ? getenv("platform") : "";
    sai_attribute_t nhg_attr;
    vector<sai_attribute_t> nhg_attrs;

    nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
    nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_FINE_GRAIN_ECMP;
    nhg_attrs.push_back(nhg_attr);

    nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_CONFIGURED_SIZE;
    nhg_attr.value.s32 = fgNhgEntry->configured_bucket_size;
    nhg_attrs.push_back(nhg_attr);

    sai_object_id_t next_hop_group_id;

    if (!gRouteOrch->createFineGrainedNextHopGroup(next_hop_group_id, nhg_attrs))
    {
        SWSS_LOG_ERROR("Failed to create next hop group %s",
                       nextHops.to_string().c_str());
        return false;
    }

    syncd_fg_route_entry.next_hop_group_id = next_hop_group_id;

    if (platform == VS_PLATFORM_SUBSTRING)
    {
       /* TODO: need implementation for SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE */ 
        fgNhgEntry->real_bucket_size = fgNhgEntry->configured_bucket_size;
    }
    else
    {
        nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE;
        nhg_attr.value.u32 = 0;
        sai_status_t status = sai_next_hop_group_api->get_next_hop_group_attribute(next_hop_group_id, 1, &nhg_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to query next hop group %s SAI_NEXT_HOP_GROUP_ATTR_REAL_SIZE, rv:%d",
                       nextHops.to_string().c_str(), status);
            if (!removeFineGrainedNextHopGroup(&syncd_fg_route_entry, fgNhgEntry))
            {
                SWSS_LOG_ERROR("Failed to clean-up after next hop group real_size query failure");
            }
            return false;
        }
        fgNhgEntry->real_bucket_size = nhg_attr.value.u32;
    }

    calculateBankHashBucketStartIndices(fgNhgEntry);

    SWSS_LOG_NOTICE("fgnhgorch created next hop group %s of size %d", nextHops.to_string().c_str(), fgNhgEntry->real_bucket_size);
    return true;
}


bool FgNhgOrch::removeFineGrainedNextHopGroup(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry)
{
    SWSS_LOG_ENTER();
    sai_status_t status;

    for (auto nhgm : syncd_fg_route_entry->nhopgroup_members)
    {
        status = sai_next_hop_group_api->remove_next_hop_group_member(nhgm);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove next hop group member %" PRIx64 ", rv:%d",
                nhgm, status);
            return false;
        }
        gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_NEXTHOP_GROUP_MEMBER);
    }

    if (!gRouteOrch->removeFineGrainedNextHopGroup(syncd_fg_route_entry->next_hop_group_id))
    {
        return false;
    }

    return true;
}


bool FgNhgOrch::createFineGrainedRouteEntry(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
        sai_object_id_t vrf_id, const IpPrefix &ipPrefix, const NextHopGroupKey &nextHops)
{
    SWSS_LOG_ENTER();
    sai_route_entry_t route_entry;
    sai_attribute_t route_attr;
    route_entry.vr_id = vrf_id;
    route_entry.switch_id = gSwitchId;
    copy(route_entry.destination, ipPrefix);
    route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    route_attr.value.oid = syncd_fg_route_entry.next_hop_group_id;
    sai_status_t status = sai_route_api->create_route_entry(&route_entry, 1, &route_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create route %s with next hop(s) %s",
                ipPrefix.to_string().c_str(), nextHops.to_string().c_str());

        /* Clean up the newly created next hop group entry */
        if (!removeFineGrainedNextHopGroup(&syncd_fg_route_entry, fgNhgEntry))
        {
            SWSS_LOG_ERROR("Failed to clean-up after route creation failure");
        }
        return false;
    }

    if (route_entry.destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
    {
        gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_IPV4_ROUTE);
    }
    else
    {
        gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_IPV6_ROUTE);
    }
    return true;
}


bool FgNhgOrch::validNextHopInNextHopGroup(const NextHopKey& nexthop)
{
    SWSS_LOG_ENTER();

    for (auto &route_tables : m_syncdFGRouteTables)
    {
        for (auto &route_table : route_tables.second)
        {
            if (!(route_table.second.nhg_key.contains(nexthop)))
            {
                continue;
            }

            FGNextHopGroupEntry *syncd_fg_route_entry = &(route_table.second);
            auto prefix_entry = fgNhgPrefixes.find(route_table.first);
            if (prefix_entry == fgNhgPrefixes.end())
            {
                SWSS_LOG_ERROR("Hit unexpected condition for %s:%s where route_table exists but no fgNhgEntry found",
                        route_table.first.to_string().c_str(), syncd_fg_route_entry->nhg_key.to_string().c_str());
                return false;
            }

            FgNhgEntry *fgNhgEntry = prefix_entry->second;
            std::map<NextHopKey,sai_object_id_t> nhopgroup_members_set;

            std::vector<BankMemberChanges> bank_member_changes(
                fgNhgEntry->hash_bucket_indices.size(), BankMemberChanges());

            if (syncd_fg_route_entry->active_nexthops.find(nexthop) !=
                    syncd_fg_route_entry->active_nexthops.end())
            {
                return true;
            }

            for (auto active_nh : syncd_fg_route_entry->active_nexthops)
            {
                bank_member_changes[fgNhgEntry->next_hops[active_nh.ip_address]].
                    active_nhs.push_back(active_nh);
            }

            bank_member_changes[fgNhgEntry->next_hops[nexthop.ip_address]].
                    nhs_to_add.push_back(nexthop);
            nhopgroup_members_set[nexthop] = m_neighOrch->getNextHopId(nexthop);

            if (!computeAndSetHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, 
                    bank_member_changes, nhopgroup_members_set, route_table.first))
            {
                SWSS_LOG_ERROR("Failed to set fine grained next hop %s",
                    nexthop.to_string().c_str());
                return false;
            }

            m_neighOrch->increaseNextHopRefCount(nexthop);
        }
    }

    return true;
}


bool FgNhgOrch::invalidNextHopInNextHopGroup(const NextHopKey& nexthop)
{
    SWSS_LOG_ENTER();

    for (auto &route_tables : m_syncdFGRouteTables)
    {
        for (auto &route_table : route_tables.second)
        {
            if (!(route_table.second.nhg_key.contains(nexthop)))
            {
                continue;
            }

            FGNextHopGroupEntry *syncd_fg_route_entry = &(route_table.second);
            auto prefix_entry = fgNhgPrefixes.find(route_table.first);
            if (prefix_entry == fgNhgPrefixes.end())
            {
                SWSS_LOG_ERROR("Hit unexpected condition for %s:%s where route_table exists but no fgNhgEntry found",
                        route_table.first.to_string().c_str(), syncd_fg_route_entry->nhg_key.to_string().c_str());
                return false;
            }

            FgNhgEntry *fgNhgEntry = prefix_entry->second;
            std::map<NextHopKey,sai_object_id_t> nhopgroup_members_set;

            std::vector<BankMemberChanges> bank_member_changes(
                fgNhgEntry->hash_bucket_indices.size(), BankMemberChanges());

            if (syncd_fg_route_entry->active_nexthops.find(nexthop) ==
                    syncd_fg_route_entry->active_nexthops.end())
            {
                return true;
            }

            for (auto active_nh : syncd_fg_route_entry->active_nexthops)
            {
                if (active_nh.ip_address == nexthop.ip_address &&
                        active_nh.alias == nexthop.alias)
                {
                    continue;
                }

                bank_member_changes[fgNhgEntry->next_hops[active_nh.ip_address]].
                    active_nhs.push_back(active_nh);

                nhopgroup_members_set[active_nh] = m_neighOrch->getNextHopId(active_nh);
            }

            bank_member_changes[fgNhgEntry->next_hops[nexthop.ip_address]].
                    nhs_to_del.push_back(nexthop);

            if (!computeAndSetHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, 
                    bank_member_changes, nhopgroup_members_set, route_table.first))
            {
                SWSS_LOG_ERROR("Failed to set fine grained next hop %s",
                    nexthop.to_string().c_str());
                return false;
            }

            m_neighOrch->decreaseNextHopRefCount(nexthop);
        }
    }

    return true;
}


/* setActiveBankHashBucketChanges: Sets hash buckets for active banks and called on a PER bank basis
 * This function deals with a scenario where next-hop changes occured for the route,
 * and the next-hop change didn't cause an entire bank to go active/inactive.
 * The function uses bank_member_changes to compute the hash buckets to modify, in order to satisy the next-hop 
 * availability for the route/neigh.
 * Eg: Prefix A had nhs 1, 2, 3 with 1, 2, 3, being equally distributed over hash buckets
 * 0-59(20 buckets per nh). If there was a nh removal of nh 2, this fn would equally redistribute hash buckets
 * for nh 2 to nh 1 and nh 3. Leading to 30 hash buckets, each, for nh 1 and nh 3, and none for nh 2. 
 * Thereby achieving consistent and layered hashing.
 */
bool FgNhgOrch::setActiveBankHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
        uint32_t bank, uint32_t syncd_bank, std::vector<BankMemberChanges> bank_member_changes, 
        std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    BankMemberChanges bank_member_change = bank_member_changes[bank];
    uint32_t add_idx = 0, del_idx = 0;
    FGNextHopGroupMap *bank_fgnhg_map = &(syncd_fg_route_entry->syncd_fgnhg_map[syncd_bank]);

    while(del_idx < bank_member_change.nhs_to_del.size() &&
            add_idx < bank_member_change.nhs_to_add.size())
    {
        HashBuckets *hash_buckets = &(bank_fgnhg_map->at(bank_member_change.nhs_to_del[del_idx]));
        for (uint32_t i = 0; i < hash_buckets->size(); i++)
        {
            if (!writeHashBucketChange(syncd_fg_route_entry, hash_buckets->at(i), 
                        nhopgroup_members_set[bank_member_change.nhs_to_add[add_idx]],
                        ipPrefix, bank_member_change.nhs_to_add[add_idx]))
            {
                return false;
            }
        }

        (*bank_fgnhg_map)[bank_member_change.nhs_to_add[add_idx]] =*hash_buckets;

        bank_fgnhg_map->erase(bank_member_change.nhs_to_del[del_idx]);
        bank_member_change.active_nhs.push_back(bank_member_change.nhs_to_add[add_idx]);
        syncd_fg_route_entry->active_nexthops.erase(bank_member_change.nhs_to_del[del_idx]);
        syncd_fg_route_entry->active_nexthops.insert(bank_member_change.nhs_to_add[add_idx]);

        del_idx++;
        add_idx++;
    }

    /* Given that we resolved add + del on a bank in the above while stmt
     * We will either have add OR delete left to do, and the logic below 
     * relies on this fact
     */
    if (del_idx < bank_member_change.nhs_to_del.size())
    {
        uint32_t num_buckets_in_bank = 1 + fgNhgEntry->hash_bucket_indices[syncd_bank].end_index -
            fgNhgEntry->hash_bucket_indices[syncd_bank].start_index;
        uint32_t exp_bucket_size = num_buckets_in_bank / (uint32_t)bank_member_change.active_nhs.size();
        uint32_t num_nhs_with_one_more = (num_buckets_in_bank % (uint32_t)bank_member_change.active_nhs.size());


        while(del_idx < bank_member_change.nhs_to_del.size())
        {
            HashBuckets *hash_buckets = &(bank_fgnhg_map->at(bank_member_change.nhs_to_del[del_idx]));
            for (uint32_t i = 0; i < hash_buckets->size(); i++)
            {
                NextHopKey round_robin_nh = bank_member_change.active_nhs[i %
                    bank_member_change.active_nhs.size()];

                if (!writeHashBucketChange(syncd_fg_route_entry, hash_buckets->at(i), 
                        nhopgroup_members_set[round_robin_nh], ipPrefix, round_robin_nh))
                {
                    return false;
                }
                bank_fgnhg_map->at(round_robin_nh).push_back(hash_buckets->at(i));

                /* Logic below ensure that # hash buckets assigned to a nh is equalized,
                 * we could have used simple round robin to reassign hash buckets to 
                 * other available nhs, but for cases where # hash buckets is not 
                 * divisible by # of nhs, simple round robin can make the hash bucket
                 * distribution non-ideal, thereby nhs can attract unequal traffic */
                if (num_nhs_with_one_more == 0)
                {
                    if (bank_fgnhg_map->at(round_robin_nh).size() == exp_bucket_size)
                    {
                        SWSS_LOG_INFO("%s reached %d, don't remove more buckets", 
                                (bank_member_change.active_nhs[i % bank_member_change.active_nhs.size()]).to_string().c_str(), 
                                exp_bucket_size);
                        bank_member_change.active_nhs.erase(bank_member_change.active_nhs.begin() + 
                            (i % bank_member_change.active_nhs.size()));
                    }
                    else if (bank_fgnhg_map->at(round_robin_nh).size() > exp_bucket_size)
                    {
                        SWSS_LOG_WARN("Unexpected bucket size for nh %s, size %lu, exp_size %d",
                                round_robin_nh.to_string().c_str(), bank_fgnhg_map->at(round_robin_nh).size(),
                                exp_bucket_size);
                    }
                }
                else
                {
                    if (bank_fgnhg_map->at(round_robin_nh).size() == exp_bucket_size +1)
                    {

                        SWSS_LOG_INFO("%s reached %d, don't remove more buckets num_nhs_with_one_more %d", 
                                (bank_member_change.active_nhs[i %bank_member_change.active_nhs.size()]).to_string().c_str(), 
                                exp_bucket_size +1, num_nhs_with_one_more -1);
                        bank_member_change.active_nhs.erase(bank_member_change.active_nhs.begin() + 
                            (i % bank_member_change.active_nhs.size()));
                        num_nhs_with_one_more--;
                    }
                    else if (bank_fgnhg_map->at(round_robin_nh).size() > exp_bucket_size +1)
                    {
                        SWSS_LOG_WARN("Unexpected bucket size for nh %s, size %lu, exp_size %d",
                                round_robin_nh.to_string().c_str(), bank_fgnhg_map->at(round_robin_nh).size(),
                                exp_bucket_size + 1);
                    }
                }
            }

            bank_fgnhg_map->erase(bank_member_change.nhs_to_del[del_idx]);
            syncd_fg_route_entry->active_nexthops.erase(bank_member_change.nhs_to_del[del_idx]);
            del_idx++;
        }
    }

    if (add_idx < bank_member_change.nhs_to_add.size())
    {
        uint32_t total_nhs = (uint32_t)bank_member_change.active_nhs.size() +
                         (uint32_t)bank_member_change.nhs_to_add.size() - add_idx;
        uint32_t num_buckets_in_bank = 1+ fgNhgEntry->hash_bucket_indices[syncd_bank].end_index -
            fgNhgEntry->hash_bucket_indices[syncd_bank].start_index;
        uint32_t exp_bucket_size = num_buckets_in_bank/total_nhs;
        uint32_t num_nhs_with_one_more = (num_buckets_in_bank % total_nhs);
        uint32_t num_nhs_with_eq_to_exp = total_nhs - num_nhs_with_one_more;
        uint32_t add_nh_exp_bucket_size = exp_bucket_size;

        while(add_idx < bank_member_change.nhs_to_add.size())
        {
            (*bank_fgnhg_map)[bank_member_change.nhs_to_add[add_idx]] = 
                std::vector<uint32_t>();
            auto it = bank_member_change.active_nhs.begin();
            if (num_nhs_with_eq_to_exp > 0)
            {
                num_nhs_with_eq_to_exp--;
            }
            else
            {
                add_nh_exp_bucket_size = exp_bucket_size + 1;
                num_nhs_with_one_more--;
            }

            while(bank_fgnhg_map->at(bank_member_change.nhs_to_add[add_idx]).size() != add_nh_exp_bucket_size)
            {
                if (it == bank_member_change.active_nhs.end())
                {
                    it = bank_member_change.active_nhs.begin();
                }
                vector<uint32_t> *map_entry = &(bank_fgnhg_map->at(*it));
                if ((*map_entry).size() <= 1)
                {
                    /* Case where the number of hash buckets for the nh is <= 1 */
                    SWSS_LOG_WARN("Next-hop %s has %d entries, either number of buckets were less or we hit a bug",
                            (*it).to_string().c_str(), ((int)(*map_entry).size()));
                    return false;
                }
                else
                {
                    uint32_t last_elem = map_entry->at((*map_entry).size() - 1);

                    if (!writeHashBucketChange(syncd_fg_route_entry, last_elem, 
                        nhopgroup_members_set[bank_member_change.nhs_to_add[add_idx]],
                        ipPrefix, bank_member_change.nhs_to_add[add_idx]))
                    {
                        return false;
                    }

                    (*bank_fgnhg_map)[bank_member_change.nhs_to_add[add_idx]].push_back(last_elem);
                    (*map_entry).erase((*map_entry).end() - 1);
                }
                /* Logic below ensure that # hash buckets assigned to a nh is equalized,
                 * we could have used simple round robin to reassign hash buckets to 
                 * other available nhs, but for cases where # hash buckets is not 
                 * divisible by # of nhs, simple round robin can make the hash bucket
                 * distribution non-ideal, thereby nhs can attract unequal traffic */
                if (num_nhs_with_one_more == 0)
                {
                    if (map_entry->size() == exp_bucket_size)
                    {
                        SWSS_LOG_INFO("%s reached %d, don't remove more buckets", it->to_string().c_str(), exp_bucket_size);
                        it = bank_member_change.active_nhs.erase(it);
                    }
                    else if (map_entry->size() < exp_bucket_size)
                    {
                        SWSS_LOG_WARN("Unexpected bucket size for nh %s, size %lu, exp_size %d",
                                it->to_string().c_str(), map_entry->size(), exp_bucket_size);
                        it++;
                    }
                    else
                    {
                        it++;
                    }
                }
                else
                {
                    if (map_entry->size() == exp_bucket_size +1)
                    {
                        SWSS_LOG_INFO("%s reached %d, don't remove more buckets num_nhs_with_one_more %d", 
                                it->to_string().c_str(), exp_bucket_size + 1, num_nhs_with_one_more -1);
                        it = bank_member_change.active_nhs.erase(it);
                        num_nhs_with_one_more--;
                    }
                    else if (map_entry->size() < exp_bucket_size)
                    {
                        SWSS_LOG_WARN("Unexpected bucket size for nh %s, size %lu, exp_size %d",
                                it->to_string().c_str(), map_entry->size(), exp_bucket_size + 1);
                        it++;
                    }
                    else
                    {
                        it++;
                    }
                }
            }
            syncd_fg_route_entry->active_nexthops.insert(bank_member_change.nhs_to_add[add_idx]);
            add_idx++;
        }
    }
    return true;
}


bool FgNhgOrch::setInactiveBankToNextAvailableActiveBank(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
        uint32_t bank, std::vector<BankMemberChanges> bank_member_changes,
        std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    uint32_t new_bank_idx = 0;
    for (; new_bank_idx < bank_member_changes.size(); new_bank_idx++)
    {
        if (bank_member_changes[new_bank_idx].active_nhs.size() +
                bank_member_changes[new_bank_idx].nhs_to_add.size() != 0)
        {
            syncd_fg_route_entry->syncd_fgnhg_map[bank].clear();
            syncd_fg_route_entry->inactive_to_active_map[bank] = new_bank_idx;

            /* Create collated set of members which will be active in the bank */
            for (auto memb: bank_member_changes[new_bank_idx].nhs_to_add)
            {
                bank_member_changes[new_bank_idx].active_nhs.push_back(memb);
            }

            for (uint32_t i = fgNhgEntry->hash_bucket_indices[bank].start_index;
                i <= fgNhgEntry->hash_bucket_indices[bank].end_index; i++)
            {
                NextHopKey bank_nh_memb = bank_member_changes[new_bank_idx].
                         active_nhs[i % bank_member_changes[new_bank_idx].active_nhs.size()];

                if (!writeHashBucketChange(syncd_fg_route_entry, i,
                    nhopgroup_members_set[bank_nh_memb],ipPrefix, bank_nh_memb ))
                {
                    return false;
                }

                syncd_fg_route_entry->syncd_fgnhg_map[bank][bank_nh_memb].push_back(i);
            }
            break;
        }
    }

    if (new_bank_idx == bank_member_changes.size())
    {
        SWSS_LOG_NOTICE("No active next-hop members were found in any bank");
        /* Case where there are no active banks */
        /* Note: There is no way to set a NULL OID to the now inactive next-hops
         * so we leave the next-hops as is in SAI, and future route/neighbor changes
         * will take care of setting the next-hops to the correctly active nhs
         */
        syncd_fg_route_entry->syncd_fgnhg_map[bank].clear();
    }

    return true;
}


/* setInactiveBankHashBucketChanges: Sets hash buckets for inactive banks and called on a PER bank basis.
 * This function deals with scenarios where next-hop changes occured for the route,
 * and the next-hop change causes an active bank to become inactive, or an inactive bank to become active or
 * inactive bank to remain inactive.
 * The function uses the bank member diffs provided in bank_member_changes and uses it to compute
 * the hash buckets to modify, in order to satisy the next-hop availability for the route/neigh.
 * Eg: Lets assume prefix A had nhs 1, 2, 3, 4, 5, 6 with nhs being equally distirbuted over hash buckets
 * 0-59(10 per nh). Now there was a nh deletion of 1, 2, 3 which constituted bank 0(4, 5, 6 constituted bank 1)
 * This function will identify that all of bank 0's nh are down and re-assign all the hash buckets(0-29) for these nhs to
 * nhs from bank 1, along with making local struct changes to track this for future route/neigh changes. 
 */
bool FgNhgOrch::setInactiveBankHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry, FgNhgEntry *fgNhgEntry,
        uint32_t bank,std::vector<BankMemberChanges> &bank_member_changes, 
        std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set, const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    if (bank_member_changes[bank].nhs_to_add.size() > 0)
    {
        /* Previously inactive bank now transistions to active */
        syncd_fg_route_entry->syncd_fgnhg_map[bank].clear();
        for (uint32_t i = fgNhgEntry->hash_bucket_indices[bank].start_index;
                i <= fgNhgEntry->hash_bucket_indices[bank].end_index; i++)
        {
            NextHopKey bank_nh_memb = bank_member_changes[bank].
                nhs_to_add[i % bank_member_changes[bank].nhs_to_add.size()];

            if (!writeHashBucketChange(syncd_fg_route_entry, i, 
                  nhopgroup_members_set[bank_nh_memb], ipPrefix, bank_nh_memb))
            {
                return false;
            }

            syncd_fg_route_entry->syncd_fgnhg_map[bank][bank_nh_memb].push_back(i);
            syncd_fg_route_entry->active_nexthops.insert(bank_nh_memb);
        }
        syncd_fg_route_entry->inactive_to_active_map[bank] = bank;
    }
    else if (bank_member_changes[bank].nhs_to_del.size() > 0)
    {
        /* Previously active bank now transistions to inactive */
        if (!setInactiveBankToNextAvailableActiveBank(syncd_fg_route_entry, fgNhgEntry,
                    bank, bank_member_changes, nhopgroup_members_set, ipPrefix))
        {
            SWSS_LOG_INFO("Failed to map to active_bank and set nh in SAI");
            return false;
        }

        for (auto memb: bank_member_changes[bank].nhs_to_del)
        {
            syncd_fg_route_entry->active_nexthops.erase(memb);
        }
    }
    else
    {
        /* Previously inactive bank remains inactive */
        uint32_t active_bank = syncd_fg_route_entry->inactive_to_active_map[bank];
        if (bank_member_changes[active_bank].active_nhs.size() == 0)
        {
            if (!setInactiveBankToNextAvailableActiveBank(syncd_fg_route_entry, fgNhgEntry,
                        bank, bank_member_changes, nhopgroup_members_set, ipPrefix))
            {
                SWSS_LOG_INFO("Failed to map to active_bank and set nh in SAI");
                return false;
            }
        }
        else
        {
            if (!setActiveBankHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, 
                active_bank, bank, bank_member_changes, nhopgroup_members_set, ipPrefix))
            {
                SWSS_LOG_INFO("Failed setActiveBankHashBucketChanges");
                return false;
            }
        }
    }
    return true;
}


bool FgNhgOrch::computeAndSetHashBucketChanges(FGNextHopGroupEntry *syncd_fg_route_entry, 
        FgNhgEntry *fgNhgEntry, std::vector<BankMemberChanges> &bank_member_changes, 
        std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set,
        const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    for (uint32_t bank_idx = 0; bank_idx < bank_member_changes.size(); bank_idx++)
    {
        if (bank_member_changes[bank_idx].active_nhs.size() != 0 ||
                (bank_member_changes[bank_idx].nhs_to_add.size() != 0 &&
                 bank_member_changes[bank_idx].nhs_to_del.size() != 0))
        {
            /* Active bank is is determined by there being active nhs on the bank OR
             * an edge case where all active_nhs went down(nhs_to_del > 0) BUT
             * simultaneously, nhs were added(nhs_to_add > 0). 
             * Route this to fn which deals with active banks
             */
            if (!setActiveBankHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, 
                        bank_idx, bank_idx, bank_member_changes, nhopgroup_members_set, ipPrefix))
            {
                return false;
            }
        }
        else
        {
            if (!setInactiveBankHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, 
                        bank_idx, bank_member_changes, nhopgroup_members_set, ipPrefix))
            {
                return false;
            }
        }
    }

    return true;
}


bool FgNhgOrch::setNewNhgMembers(FGNextHopGroupEntry &syncd_fg_route_entry, FgNhgEntry *fgNhgEntry, 
        std::vector<BankMemberChanges> &bank_member_changes, std::map<NextHopKey,sai_object_id_t> &nhopgroup_members_set,
        const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    sai_status_t status;
    for (uint32_t i = 0; i < fgNhgEntry->hash_bucket_indices.size(); i++) 
    {
        uint32_t bank = i;
        syncd_fg_route_entry.inactive_to_active_map[bank] = bank;
        if (i + 1 > syncd_fg_route_entry.syncd_fgnhg_map.size())
        {
            syncd_fg_route_entry.syncd_fgnhg_map.push_back(FGNextHopGroupMap());
        }

        if (bank_member_changes[i].nhs_to_add.size() == 0)
        {
            /* Case where bank is empty */
            for (uint32_t active_bank = 0; active_bank < bank_member_changes.size(); active_bank++)
            {
                if (bank_member_changes[active_bank].nhs_to_add.size() != 0)
                {
                    bank = active_bank;
                    syncd_fg_route_entry.inactive_to_active_map[i] = active_bank;
                    break;
                }
            }
        } 

        if (bank_member_changes[bank].nhs_to_add.size() == 0)
        {
            /* Case where all banks are empty, we let retry logic(upon rv false) take care of this scenario */
            SWSS_LOG_INFO("Found no next-hops to add, skipping");
            return false;
        }

        for (uint32_t j = fgNhgEntry->hash_bucket_indices[i].start_index;
                j <= fgNhgEntry->hash_bucket_indices[i].end_index; j++)
        {
            NextHopKey bank_nh_memb = bank_member_changes[bank].nhs_to_add[j % 
                bank_member_changes[bank].nhs_to_add.size()];

            // Create a next hop group member
            sai_attribute_t nhgm_attr;
            vector<sai_attribute_t> nhgm_attrs;
            nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            nhgm_attr.value.oid = syncd_fg_route_entry.next_hop_group_id;
            nhgm_attrs.push_back(nhgm_attr);

            nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            nhgm_attr.value.oid = nhopgroup_members_set[bank_nh_memb];
            nhgm_attrs.push_back(nhgm_attr);

            nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_INDEX;
            nhgm_attr.value.s32 = j;
            nhgm_attrs.push_back(nhgm_attr);

            sai_object_id_t next_hop_group_member_id;
            status = sai_next_hop_group_api->create_next_hop_group_member(
                                                              &next_hop_group_member_id,
                                                              gSwitchId,
                                                              (uint32_t)nhgm_attrs.size(),
                                                              nhgm_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("Failed to create next hop group %" PRIx64 " member %" PRIx64 ": %d",
                   syncd_fg_route_entry.next_hop_group_id, next_hop_group_member_id, status);
                
                if (!removeFineGrainedNextHopGroup(&syncd_fg_route_entry, fgNhgEntry))
                {
                    SWSS_LOG_ERROR("Failed to clean-up after next-hop member creation failure");
                }
                
                return false;
            }

            setStateDbRouteEntry(ipPrefix, j, bank_nh_memb);
            syncd_fg_route_entry.syncd_fgnhg_map[i][bank_nh_memb].push_back(j);
            syncd_fg_route_entry.active_nexthops.insert(bank_nh_memb);
            syncd_fg_route_entry.nhopgroup_members.push_back(next_hop_group_member_id);
            gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_NEXTHOP_GROUP_MEMBER);
        }
    }

    return true;
}


bool FgNhgOrch::addRoute(sai_object_id_t vrf_id, const IpPrefix &ipPrefix, const NextHopGroupKey &nextHops)
{
    SWSS_LOG_ENTER();

    if (m_syncdFGRouteTables.find(vrf_id) != m_syncdFGRouteTables.end() &&
        m_syncdFGRouteTables.at(vrf_id).find(ipPrefix) != m_syncdFGRouteTables.at(vrf_id).end() &&
        m_syncdFGRouteTables.at(vrf_id).at(ipPrefix).nhg_key == nextHops)
    {
        return true;
    }

    if (m_syncdFGRouteTables.find(vrf_id) == m_syncdFGRouteTables.end())
    {
        m_syncdFGRouteTables.emplace(vrf_id, FGRouteTable());
        m_vrfOrch->increaseVrfRefCount(vrf_id);
    }

    auto prefix_entry = fgNhgPrefixes.find(ipPrefix);
    assert(prefix_entry != fgNhgPrefixes.end());
    FgNhgEntry *fgNhgEntry = prefix_entry->second;

    set<NextHopKey> next_hop_set = nextHops.getNextHops();
    std::map<NextHopKey,sai_object_id_t> nhopgroup_members_set;
    auto syncd_fg_route_entry_it = m_syncdFGRouteTables.at(vrf_id).find(ipPrefix);
    bool next_hop_to_add = false;

    /* Default init with # of banks */
    std::vector<BankMemberChanges> bank_member_changes(
            fgNhgEntry->hash_bucket_indices.size(), BankMemberChanges());
    if (fgNhgEntry->hash_bucket_indices.size() == 0)
    {
        /* Only happens the 1st time when hash_bucket_indices are not inited
         */
        for (auto it : fgNhgEntry->next_hops)
        {
            while(bank_member_changes.size() <= it.second)
            {
                bank_member_changes.push_back(BankMemberChanges());
            }
        }
    }

    /* Assert each IP address exists in m_syncdNextHops table,
     * and add the corresponding next_hop_id to next_hop_ids. */
    for (NextHopKey nhk : next_hop_set)
    {
        if (!m_neighOrch->hasNextHop(nhk))
        {
            SWSS_LOG_NOTICE("Failed to get next hop %s:%s in neighorch",
                    nhk.to_string().c_str(), nextHops.to_string().c_str());
            continue;
        }
        else if (fgNhgEntry->next_hops.find(nhk.ip_address) == fgNhgEntry->next_hops.end())
        {
            SWSS_LOG_WARN("Could not find next-hop %s in Fine Grained next-hop group entry for prefix %s, skipping",
                    nhk.to_string().c_str(), fgNhgEntry->fg_nhg_name.c_str());
            continue;
        }
        else if (m_neighOrch->isNextHopFlagSet(nhk, NHFLAGS_IFDOWN))
        {
            SWSS_LOG_NOTICE("Next hop %s in %s is down, skipping",
                    nhk.to_string().c_str(), nextHops.to_string().c_str());
            continue;
        }

        if (syncd_fg_route_entry_it == m_syncdFGRouteTables.at(vrf_id).end())
        {
            bank_member_changes[fgNhgEntry->next_hops[nhk.ip_address]].
                nhs_to_add.push_back(nhk);
            next_hop_to_add = true;
        }
        else 
        {
            FGNextHopGroupEntry *syncd_fg_route_entry = &(syncd_fg_route_entry_it->second);
            if (syncd_fg_route_entry->active_nexthops.find(nhk) == 
                syncd_fg_route_entry->active_nexthops.end())
            {
                bank_member_changes[fgNhgEntry->next_hops[nhk.ip_address]].
                    nhs_to_add.push_back(nhk);
            }
        }

        sai_object_id_t next_hop_id = m_neighOrch->getNextHopId(nhk);
        nhopgroup_members_set[nhk] = next_hop_id;
    }

    if (syncd_fg_route_entry_it != m_syncdFGRouteTables.at(vrf_id).end())
    {
        FGNextHopGroupEntry *syncd_fg_route_entry = &(syncd_fg_route_entry_it->second);

        /* Route exists, update FG ECMP group in SAI */
        for (auto nhk : syncd_fg_route_entry->active_nexthops)
        {
            if (nhopgroup_members_set.find(nhk) == nhopgroup_members_set.end())
            {
                bank_member_changes[fgNhgEntry->next_hops[nhk.ip_address]].
                    nhs_to_del.push_back(nhk);
            }
            else
            {
                bank_member_changes[fgNhgEntry->next_hops[nhk.ip_address]].
                    active_nhs.push_back(nhk);
            }
        }

        if (!computeAndSetHashBucketChanges(syncd_fg_route_entry, fgNhgEntry, bank_member_changes, 
                nhopgroup_members_set, ipPrefix))
        {
            return false;
        }
    }
    else
    {
        /* New route + nhg addition */
        if (next_hop_to_add == false)
        {
            SWSS_LOG_INFO("There were no valid next-hops to add %s:%s", ipPrefix.to_string().c_str(),
                    nextHops.to_string().c_str());
            /* Let the route retry logic(upon false rc) take care of this case */
            return false;
        }

        FGNextHopGroupEntry syncd_fg_route_entry;
        if (!createFineGrainedNextHopGroup(syncd_fg_route_entry, fgNhgEntry, nextHops))
        {
            return false;
        }

        if (!setNewNhgMembers(syncd_fg_route_entry, fgNhgEntry, bank_member_changes, nhopgroup_members_set, ipPrefix))
        {
            return false;
        }

        if (!createFineGrainedRouteEntry(syncd_fg_route_entry, fgNhgEntry, vrf_id, ipPrefix, nextHops))
        {
            return false;
        }

        m_syncdFGRouteTables[vrf_id][ipPrefix] = syncd_fg_route_entry;

        SWSS_LOG_NOTICE("Created route %s:%s", ipPrefix.to_string().c_str(), nextHops.to_string().c_str());
    }
    m_syncdFGRouteTables[vrf_id][ipPrefix].nhg_key = nextHops; 

    for (uint32_t bank_idx = 0; bank_idx < bank_member_changes.size(); bank_idx++)
    {
        for (auto nh : bank_member_changes[bank_idx].nhs_to_add)
        {
            m_neighOrch->increaseNextHopRefCount(nh);
        }

        for (auto nh : bank_member_changes[bank_idx].nhs_to_del)
        {
            m_neighOrch->decreaseNextHopRefCount(nh);
        }
    }

    return true;
}


bool FgNhgOrch::removeRoute(sai_object_id_t vrf_id, const IpPrefix &ipPrefix)
{
    SWSS_LOG_ENTER();

    auto it_route_table = m_syncdFGRouteTables.find(vrf_id);
    if (it_route_table == m_syncdFGRouteTables.end())
    {
        SWSS_LOG_INFO("No route table found for %s, vrf_id 0x%" PRIx64, 
                ipPrefix.to_string().c_str(), vrf_id);
        return true;
    }

    auto it_route = it_route_table->second.find(ipPrefix);
    if (it_route == it_route_table->second.end())
    {
        SWSS_LOG_INFO("Failed to find route entry, vrf_id 0x%" PRIx64 ", prefix %s", vrf_id,
                ipPrefix.to_string().c_str());
        return true;
    }

    auto prefix_entry = fgNhgPrefixes.find(ipPrefix);
    assert(prefix_entry != fgNhgPrefixes.end());
    FgNhgEntry *fgNhgEntry = prefix_entry->second;

    sai_route_entry_t route_entry;
    route_entry.vr_id = vrf_id;
    route_entry.switch_id = gSwitchId;
    copy(route_entry.destination, ipPrefix);
    sai_status_t status = sai_route_api->remove_route_entry(&route_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove route prefix:%s", ipPrefix.to_string().c_str());
        return false;
    }

    if (route_entry.destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
    {
        gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_IPV4_ROUTE);
    }
    else
    {
        gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_IPV6_ROUTE);
    }

    FGNextHopGroupEntry *syncd_fg_route_entry = &(it_route->second);
    if (!removeFineGrainedNextHopGroup(syncd_fg_route_entry, fgNhgEntry))
    {
        SWSS_LOG_ERROR("Failed to clean-up fine grained ECMP SAI group");
        return false;
    }

    for (auto nh : syncd_fg_route_entry->active_nexthops)
    {
        m_neighOrch->decreaseNextHopRefCount(nh);
    }

    // remove state_db entry
    m_stateWarmRestartRouteTable.del(ipPrefix.to_string());

    it_route_table->second.erase(it_route);
    if (it_route_table->second.size() == 0)
    {
	    m_syncdFGRouteTables.erase(vrf_id);
	    m_vrfOrch->decreaseVrfRefCount(vrf_id);
    }
    return true;
}


bool FgNhgOrch::doTaskFgNhg(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();
    string op = kfvOp(t);
    string key = kfvKey(t);
    string fg_nhg_name = key; 
    auto fgNhg_entry = m_FgNhgs.find(fg_nhg_name);

    if (op == SET_COMMAND)
    {
        uint32_t bucket_size = 0;

        for (auto i : kfvFieldsValues(t))
        {
            if (fvField(i) == "bucket_size")
            {
                bucket_size = stoi(fvValue(i));
            }
        }

        if (bucket_size == 0)
        {
            SWSS_LOG_ERROR("Received bucket_size which is 0 for key %s", kfvKey(t).c_str());
            return true;
        }

        if (fgNhg_entry != m_FgNhgs.end()) 
        {
            if (bucket_size != (fgNhg_entry->second).configured_bucket_size)
            {
                SWSS_LOG_WARN("Received request to change %s's bucket size to %d, unsupported operation, skipping",
                        fg_nhg_name.c_str(), bucket_size);
                return true;
            }
        }
        else
        {
            FgNhgEntry fgNhgEntry;
            fgNhgEntry.configured_bucket_size = bucket_size;
            fgNhgEntry.fg_nhg_name = fg_nhg_name;
            SWSS_LOG_INFO("Added new FG_NHG entry with configured_bucket_size %d", 
                    fgNhgEntry.configured_bucket_size);
            m_FgNhgs[fg_nhg_name] = fgNhgEntry;
        }
    }
    else if (op == DEL_COMMAND)
    {
        if (fgNhg_entry == m_FgNhgs.end())
        {
            SWSS_LOG_INFO("Received delete call for non-existent entry %s",
                    fg_nhg_name.c_str());
        }
        else 
        {
            /* Check if there are no child objects associated prior to deleting */
            if (fgNhg_entry->second.prefixes.size() == 0 && fgNhg_entry->second.next_hops.size() == 0)
            {
                m_FgNhgs.erase(fgNhg_entry);
                assert(m_FgNhgs.find(fg_nhg_name) == fgNhgPrefixes.end());
                SWSS_LOG_INFO("Received delete call for valid entry with no further dependencies, deleting %s",
                        fg_nhg_name.c_str());
            }
            else
            {
                SWSS_LOG_INFO("Child Prefix/Member entries are still associated with this FG_NHG %s", 
                        fg_nhg_name.c_str());
                return false;
            }
        }
    }
    return true;
}


vector<FieldValueTuple> FgNhgOrch::generateRouteTableFromNhgKey(NextHopGroupKey nhg)
{
    SWSS_LOG_ENTER();
    vector<FieldValueTuple> fvVector;
    std::set<NextHopKey> nhks = nhg.getNextHops();
    string nexthops = nhks.begin()->ip_address.to_string();
    string ifnames = nhks.begin()->alias;

    for (auto nhk: nhks)
    {
        if (nhk == *(nhks.begin()))
        {
            continue;
        }
        nexthops += "," + nhk.ip_address.to_string();
        ifnames += "," + nhk.alias;
    }

    FieldValueTuple nh("nexthop", nexthops);
    FieldValueTuple idx("ifname", ifnames);
    SWSS_LOG_INFO("Generated fv nhs %s, fv ifnames %s", nexthops.c_str(), ifnames.c_str());

    fvVector.push_back(nh);
    fvVector.push_back(idx);
    return fvVector;
}


bool FgNhgOrch::doTaskFgNhgPrefix(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();
    string op = kfvOp(t);
    string key = kfvKey(t);
    IpPrefix ip_prefix = IpPrefix(key);
    auto prefix_entry = fgNhgPrefixes.find(ip_prefix);

    if (op == SET_COMMAND)
    {
        if (prefix_entry != fgNhgPrefixes.end())
        {
            SWSS_LOG_INFO("FG_NHG prefix already exists");
            return true;
        }

        string fg_nhg_name = "";
        for (auto i : kfvFieldsValues(t))
        {
            if (fvField(i) == "FG_NHG")
            {
                fg_nhg_name = fvValue(i);
            }
        }
        if (fg_nhg_name.empty())
        {
            SWSS_LOG_ERROR("Received FG_NHG with empty name for key %s", kfvKey(t).c_str());
            return true;
        }

        auto fgNhg_entry = m_FgNhgs.find(fg_nhg_name);
        if (fgNhg_entry == m_FgNhgs.end())
        {
            SWSS_LOG_INFO("FG_NHG entry not received yet, continue");
            return false;
        }

        /* delete regular ecmp handling for prefix */
        sai_object_id_t vrf_id = gVirtualRouterId;
        NextHopGroupKey nhg = gRouteOrch->getSyncdRouteNhgKey(vrf_id, ip_prefix);
        auto addCache = m_fgPrefixAddCache.find(ip_prefix);
        if (addCache == m_fgPrefixAddCache.end())
        {
            if (nhg.getSize() == 0)
            {
                SWSS_LOG_INFO("Route does not exist in routeorch, don't need to migrate route to fgnhgorch");
                fgNhg_entry->second.prefixes.push_back(ip_prefix);
                fgNhgPrefixes[ip_prefix] = &(fgNhg_entry->second);
            }
            else
            {
                SWSS_LOG_INFO("Route exists in routeorch, deleting from APP_DB to begin migration");
                m_fgPrefixAddCache[ip_prefix] = nhg;
                m_routeTable.del(ip_prefix.to_string());
                return false;
            }
        }
        else
        {
            if (nhg.getSize() == 0)
            {
                /* Case where APP_DB route entry was present and the route delete was completed */
                SWSS_LOG_INFO("Route removed in routeorch, now do an APP_DB addition");
                fgNhg_entry->second.prefixes.push_back(ip_prefix);
                fgNhgPrefixes[ip_prefix] = &(fgNhg_entry->second);
                m_routeTable.set(ip_prefix.to_string(), generateRouteTableFromNhgKey(addCache->second));
                m_fgPrefixAddCache.erase(addCache);
                SWSS_LOG_INFO("Performed APP_DB addition with prefix %s", ip_prefix.to_string().c_str());
            }
            else
            {
                SWSS_LOG_INFO("Route exists in routeorch, and APP_DB route was deleted, waiting for routeorch delete to complete");
                return false;
            }
        }
        SWSS_LOG_INFO("FG_NHG added for group %s, prefix %s",
                fgNhgPrefixes[ip_prefix]->fg_nhg_name.c_str(), ip_prefix.to_string().c_str());
    }
    else if (op == DEL_COMMAND)
    {
        if (prefix_entry == fgNhgPrefixes.end())
        {
            SWSS_LOG_INFO("FG_NHG prefix doesn't exists, ignore");
            return true;
        }
        /* delete fine grained ecmp handling for prefix */
        auto fgNhg_entry = prefix_entry->second;
        sai_object_id_t vrf_id = gVirtualRouterId;
        NextHopGroupKey nhg;
        if (m_syncdFGRouteTables.find(vrf_id) != m_syncdFGRouteTables.end() &&
                    m_syncdFGRouteTables.at(vrf_id).find(ip_prefix) != m_syncdFGRouteTables.at(vrf_id).end())
        {
            nhg = m_syncdFGRouteTables.at(vrf_id).at(ip_prefix).nhg_key;
        } 

        auto delCache = m_fgPrefixDelCache.find(ip_prefix);
        if (delCache == m_fgPrefixDelCache.end())
        {
            if (nhg.getSize() == 0)
            {
                SWSS_LOG_INFO("Route does not exist in fgnhgorch, proceed with deletion of local structures");
                for (uint32_t i = 0; i < fgNhg_entry->prefixes.size(); i++)
                {
                    if(fgNhg_entry->prefixes[i] == ip_prefix)
                    {
                        fgNhg_entry->prefixes.erase(fgNhg_entry->prefixes.begin() + i);
                        break;
                    }
                }

                fgNhgPrefixes.erase(ip_prefix); 
            }
            else
            {
                SWSS_LOG_INFO("Route exists in fgNhgOrch, deleting from APP_DB");
                m_fgPrefixDelCache[ip_prefix] = nhg;
                m_routeTable.del(ip_prefix.to_string());
                return false;
            }
        }
        else
        {
            if (nhg.getSize() == 0)
            {
                /* Case where fgnhgorch route entry was present and the route delete was completed */
                SWSS_LOG_INFO("Route removed in fgNhgOrch, now do an APP_DB addition");
                for (uint32_t i = 0; i < fgNhg_entry->prefixes.size(); i++)
                {
                    if (fgNhg_entry->prefixes[i] == ip_prefix)
                    {
                        fgNhg_entry->prefixes.erase(fgNhg_entry->prefixes.begin() + i);
                        break;
                    }
                }
                fgNhgPrefixes.erase(ip_prefix); 

                m_routeTable.set(ip_prefix.to_string(), generateRouteTableFromNhgKey(delCache->second));
                SWSS_LOG_INFO("Perform APP_DB addition with prefix %s", ip_prefix.to_string().c_str());
            }
            else
            {
                SWSS_LOG_INFO("Route exists in fgNhgOrch, and APP_DB route was deleted, waiting for fgNhgOrch delete to complete");
                return false;
            }
        }
        SWSS_LOG_INFO("FG_NHG removed for group prefix %s", ip_prefix.to_string().c_str());

    }
    return true;
}


bool FgNhgOrch::doTaskFgNhgMember(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();
    string op = kfvOp(t);
    string key = kfvKey(t);
    IpAddress next_hop = IpAddress(key);
    NextHopKey nhk(next_hop.to_string());

    if (op == SET_COMMAND)
    {
        string fg_nhg_name = "";
        uint32_t bank = 0;
        for (auto i : kfvFieldsValues(t))
        {
            if (fvField(i) == "FG_NHG")
            {
                fg_nhg_name = fvValue(i);
            }
            else if (fvField(i) == "bank")
            {
                bank = stoi(fvValue(i));
            }
        }
        if (fg_nhg_name.empty())
        {
            SWSS_LOG_ERROR("Received FG_NHG with empty name for key %s", kfvKey(t).c_str());
            return true;
        }

        auto fgNhg_entry = m_FgNhgs.find(fg_nhg_name);
        if (fgNhg_entry == m_FgNhgs.end())
        {
            SWSS_LOG_INFO("FG_NHG entry not received yet, continue");
            return false;
        }
        else
        {
            /* skip addition if next-hop already exists */
            if (fgNhg_entry->second.next_hops.find(next_hop) != fgNhg_entry->second.next_hops.end())
            {
                SWSS_LOG_INFO("FG_NHG member %s already exists, skip", next_hop.to_string().c_str());
                return true;
            }
            fgNhg_entry->second.next_hops[next_hop] = bank;

            /* query and check the next hop is valid in neighOrcch */
            if (!m_neighOrch->hasNextHop(nhk))
            {
                SWSS_LOG_INFO("Nexthop %s is not resolved yet", nhk.to_string().c_str());
                return true;
            }

            /* add next-hop into SAI group */
            if (!validNextHopInNextHopGroup(nhk))
            {
                return false;
            }
            SWSS_LOG_INFO("FG_NHG member added for group %s, next-hop %s",
                    fgNhg_entry->second.fg_nhg_name.c_str(), next_hop.to_string().c_str());
        }
    }
    else if (op == DEL_COMMAND)
    {
        /* remove next hop from SAI group if its a resolved nh which is programmed to SAI*/
        if (m_neighOrch->hasNextHop(nhk))
        {
            if (!invalidNextHopInNextHopGroup(nhk))
            {
                return false;
            }
        }

        SWSS_LOG_INFO("FG_NHG member removed for SAI group, next-hop %s",
                next_hop.to_string().c_str());

        /* remove next-hop in fgnhg entry*/
        for (auto fgnhg_it = m_FgNhgs.begin(); fgnhg_it != m_FgNhgs.end(); ++fgnhg_it)
        {
            auto it = fgnhg_it->second.next_hops.find(next_hop);
            if (it != fgnhg_it->second.next_hops.end())
            {
                SWSS_LOG_INFO("FG_NHG member removed for group %s, next-hop %s",
                        fgnhg_it->second.fg_nhg_name.c_str(), next_hop.to_string().c_str());
                fgnhg_it->second.next_hops.erase(it);
            }
        }
    }
    return true;
}
        

void FgNhgOrch::doTask(Consumer& consumer) 
{
    SWSS_LOG_ENTER();
    const string & table_name = consumer.getTableName();
    auto it = consumer.m_toSync.begin();
    bool entry_handled = true;

    while (it != consumer.m_toSync.end())
    {
        auto t = it->second;
        if (table_name == CFG_FG_NHG)
        {
            entry_handled = doTaskFgNhg(t);
        }
        else if (table_name == CFG_FG_NHG_PREFIX)
        {
            entry_handled = doTaskFgNhgPrefix(t);
        }
        else if (table_name == CFG_FG_NHG_MEMBER)
        {
            entry_handled = doTaskFgNhgMember(t);
        }
        else
        {
            entry_handled = true;
            SWSS_LOG_ERROR("Unknown table : %s", table_name.c_str());
        }

        if (entry_handled)
        {
            consumer.m_toSync.erase(it++);
        }
        else
        {
            it++;
        }
    }
    return;
}
