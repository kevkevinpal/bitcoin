#include <private_broadcast.h>
#include <primitives/transaction.h>
#include <net.h>
#include <util/time.h>
#include <unordered_map>
#include <vector>
#include <consensus/tx_check.h>
#include <consensus/validation.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>

static constexpr size_t MAX_TXIDS = 1000;
static constexpr size_t MAX_PENDING_NODE_IDS = 100;

FUZZ_TARGET(private_broadcast)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(provider));
    PrivateBroadcast pb;

    std::vector<Txid> current_txids;
    current_txids.reserve(MAX_TXIDS);
    std::unordered_map<Txid, CTransactionRef, SaltedTxidHasher> tx_map;

    std::vector<NodeId> pending_nodeids;
    pending_nodeids.reserve(MAX_PENDING_NODE_IDS);

    while (provider.remaining_bytes() > 0) {
        uint8_t operation = provider.ConsumeIntegralInRange<uint8_t>(0, 6);
        switch (operation) {
            case 0: { // Add
                if (current_txids.size() >= MAX_TXIDS)
                    break;
                const bool with_witness = provider.ConsumeBool();
                auto tx = ConsumeDeserializable<CMutableTransaction>(provider, with_witness ? TX_WITH_WITNESS : TX_NO_WITNESS);
                if (tx) {
                    if (provider.remaining_bytes() < sizeof(Txid)) {
                        break; // Not enough data for a valid Txid
                    }
                    TxValidationState state_with_dupe_check;
                    CTransaction ctx = CTransaction((std::move(*tx)));
                    const bool res{CheckTransaction(ctx, state_with_dupe_check)};
                    Assert(res == state_with_dupe_check.IsValid());

                    CTransactionRef tx_ref = MakeTransactionRef(std::move(*tx));
                    Txid txid = tx->GetHash();
                    if (pb.Add(tx_ref)) {
                        current_txids.push_back(txid);
                        tx_map[txid] = tx_ref;
                    }
                }
                break;
            }
            case 1: { // Remove
                if (!current_txids.empty()) {
                    uint8_t index = provider.ConsumeIntegralInRange<uint8_t>(0, current_txids.size() - 1);
                    Txid txid = current_txids[index];
                    auto it = tx_map.find(txid);
                    if (it != tx_map.end()) {
                        std::optional<size_t> removed = pb.Remove(it->second);
                        if (removed) {
                            current_txids.erase(current_txids.begin() + index);
                            tx_map.erase(it);
                        }
                    }
                }
                break;
            }
            case 2: { // GetTxForBroadcast
                pb.GetTxForBroadcast();
                break;
            }
            case 3: { // PushedToNode
                if (!current_txids.empty() && pending_nodeids.size() < MAX_PENDING_NODE_IDS - 1) {
                    NodeId nodeid = provider.ConsumeIntegral<NodeId>();
                    uint8_t index = provider.ConsumeIntegralInRange<uint8_t>(0, current_txids.size() - 1);
                    Txid txid = current_txids[index];
                    pb.PushedToNode(nodeid, txid);
                    pending_nodeids.push_back(nodeid);
                }
                break;
            }
            case 4: { // GetTxPushedToNode
                if (!pending_nodeids.empty()) {
                    uint8_t index = provider.ConsumeIntegralInRange<uint8_t>(0, pending_nodeids.size() - 1);
                    NodeId nodeid = pending_nodeids[index];
                    pb.GetTxPushedToNode(nodeid);
                }
                break;
            }
            case 5: { // FinishBroadcast
                if (!pending_nodeids.empty()) {
                    uint8_t index = provider.ConsumeIntegralInRange<uint8_t>(0, pending_nodeids.size() - 1);
                    NodeId nodeid = pending_nodeids[index];
                    bool confirmed = provider.ConsumeBool();
                    pb.FinishBroadcast(nodeid, confirmed);
                    pending_nodeids.erase(pending_nodeids.begin() + index);
                }
                break;
            }
            case 6: { // GetStale
                pb.GetStale();
                break;
            }
        }
    }
}
