/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ISL_INTERRUPTION_EXPERIMENT_H
#define ISL_INTERRUPTION_EXPERIMENT_H

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include "ns3/basic-simulation.h"
#include "ns3/error-model.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/object-vector.h"
#include "ns3/pointer.h"
#include "ns3/point-to-point-laser-net-device.h"
#include "ns3/simulator.h"
#include "ns3/tcp-flow-schedule-reader.h"
#include "ns3/tcp-flow-sink.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/topology-satellite-network.h"

namespace ns3 {

/** Discard every received frame while enabled, without consuming random numbers. */
class IslInterruptionErrorModel : public ErrorModel {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::IslInterruptionErrorModel")
            .SetParent<ErrorModel>().AddConstructor<IslInterruptionErrorModel>();
        return tid;
    }
private:
    bool DoCorrupt(Ptr<Packet>) override { return IsEnabled(); }
    void DoReset() override {}
};

/**
 * Schedule one bidirectional ISL interruption and optionally record TCP flow metrics.
 *
 * Both features are disabled by default and can be enabled independently.
 * Forwarding continues to follow the configured routing schedule during the outage.
 * Measurements support one TCP flow (ID 0, starting at time 0). MPI is not supported.
 */
class IslInterruptionExperiment {
public:
    /** Read experiment settings, attach enabled traces, and schedule interruption events. */
    IslInterruptionExperiment(Ptr<BasicSimulation> simulation, Ptr<TopologySatelliteNetwork> topology)
        : m_simulation(simulation), m_topology(topology) {
        m_measure = parse_boolean(simulation->GetConfigParamOrDefault("enable_tcp_flow_measurements", "false"));
        m_outage = parse_boolean(simulation->GetConfigParamOrDefault("enable_isl_interruption", "false"));
        int64_t source = ReadInteger("tcp_flow_measurement_source_node", "-1");
        int64_t target = ReadInteger("tcp_flow_measurement_target_node", "-1");
        int64_t a = ReadInteger("isl_interruption_node_a", "-1");
        int64_t b = ReadInteger("isl_interruption_node_b", "-1");
        int64_t start = ReadInteger("isl_interruption_start_ns", "0");
        int64_t duration = ReadInteger("isl_interruption_duration_ns", "0");
        if (!m_measure && !m_outage) { return; }
        if (simulation->IsDistributedEnabled()) {
            throw std::invalid_argument("ISL interruptions and TCP flow measurements require a single simulator process.");
        }
        const NodeContainer& nodes = topology->GetNodes();
        if (m_measure) {
            if (source < 0 || target < 0 || source == target ||
                source >= nodes.GetN() || target >= nodes.GetN()) {
                throw std::invalid_argument("Set valid, distinct tcp_flow_measurement_source_node and tcp_flow_measurement_target_node values.");
            }
            m_source = static_cast<uint32_t>(source);
            m_target = static_cast<uint32_t>(target);
            auto schedule = read_tcp_flow_schedule(
                simulation->GetRunDir() + "/" + simulation->GetConfigParamOrFail("tcp_flow_schedule_filename"),
                topology, simulation->GetSimulationEndTimeNs());
            if (schedule.size() != 1 || schedule[0].GetTcpFlowId() != 0 ||
                schedule[0].GetStartTimeNs() != 0 || schedule[0].GetFromNodeId() != source ||
                schedule[0].GetToNodeId() != target) {
                throw std::invalid_argument("TCP flow measurements require exactly flow 0, starting at time 0, between the configured nodes.");
            }
            Open(m_received, "tcp_flow_0_received.csv", "flow_id,time_ns,received_bytes\n");
            m_received << "0,0,0\n";
            Open(m_tx, "tcp_flow_0_tx.csv", "flow_id,time_ns,sequence,payload_bytes,retransmitted_bytes\n");
            Open(m_retransmissions, "tcp_flow_0_retransmissions.csv", "flow_id,time_ns,sequence,payload_bytes,retransmitted_bytes\n");
            uint32_t connected = 0;
            Ptr<Node> receiver = nodes.Get(m_target);
            for (uint32_t i = 0; i < receiver->GetNApplications(); ++i) {
                Ptr<TcpFlowSink> sink = DynamicCast<TcpFlowSink>(receiver->GetApplication(i));
                if (sink && sink->TraceConnectWithoutContext("Rx", MakeCallback(&IslInterruptionExperiment::Received, this))) {
                    ++connected;
                }
            }
            if (connected != 1) { throw std::runtime_error("Expected exactly one TcpFlowSink with an Rx trace on the measurement target node."); }
            // The scheduler creates the source application/socket in time-0 events.
            // Connect before the handshake can finish; pure SYN/ACKs are not counted.
            Simulator::Schedule(NanoSeconds(1), &IslInterruptionExperiment::ConnectSender, this);
        }
        if (m_outage) {
            if (a < 0 || b < 0 || a == b ||
                static_cast<size_t>(a) >= topology->GetSatellites().size() ||
                static_cast<size_t>(b) >= topology->GetSatellites().size() ||
                start <= 0 || duration <= 0 || start >= simulation->GetSimulationEndTimeNs() ||
                duration >= simulation->GetSimulationEndTimeNs() - start) {
                throw std::invalid_argument("Set valid, distinct ISL endpoint nodes and positive interruption times ending before the simulation ends.");
            }
            m_a = static_cast<uint32_t>(a);
            m_b = static_cast<uint32_t>(b);
            Ptr<PointToPointLaserNetDevice> deviceA = FindIsl(m_a, m_b);
            Ptr<PointToPointLaserNetDevice> deviceB = FindIsl(m_b, m_a);
            m_errorA = InstallLossModel(deviceA);
            m_errorB = InstallLossModel(deviceB);
            deviceA->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&IslInterruptionExperiment::DropAtA, this));
            deviceB->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&IslInterruptionExperiment::DropAtB, this));
            Open(m_events, "isl_interruption_events.csv", "time_ns,event,node_a,node_b\n");
            Open(m_drops, "isl_interruption_drops.csv", "time_ns,from_node,to_node,frame_bytes\n");
            Simulator::Schedule(NanoSeconds(start), &IslInterruptionExperiment::SetInterrupted, this, true);
            Simulator::Schedule(NanoSeconds(start + duration), &IslInterruptionExperiment::SetInterrupted, this, false);
        }
    }

    /** Validate completed observations, write the final receiver sample, and close logs. */
    void Finalize() {
        if (m_measure) {
            if (!m_sender || m_transmittedPackets == 0) {
                throw std::runtime_error("TCP measurements recorded no data transmissions; check the flow configuration and simulation duration.");
            }
            m_received << "0," << m_simulation->GetSimulationEndTimeNs() << "," << m_receivedBytes << "\n";
            m_received.close();
            m_tx.close();
            m_retransmissions.close();
        }
        if (m_outage) {
            if (m_eventCount != 2) { throw std::runtime_error("The interruption did not start and end."); }
            m_events.close();
            m_drops.close();
        }
    }

private:
    int64_t ReadInteger(const std::string& key, const std::string& fallback) {
        std::string value = m_simulation->GetConfigParamOrDefault(key, fallback);
        size_t used = 0;
        int64_t number = std::stoll(value, &used);
        if (used != value.size()) { throw std::invalid_argument("Invalid integer: " + key); }
        return number;
    }
    void Open(std::ofstream& output, const std::string& name, const std::string& header) {
        output.exceptions(std::ios::badbit | std::ios::failbit);
        output.open(m_simulation->GetLogsDir() + "/" + name);
        output << header;
    }
    void ConnectSender() {
        ObjectVectorValue sockets;
        m_topology->GetNodes().Get(m_source)->GetObject<TcpL4Protocol>()->GetAttribute("SocketList", sockets);
        Ipv4Address target = m_topology->GetNodes().Get(m_target)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
        uint32_t connected = 0;
        for (uint32_t i = 0; i < sockets.GetN(); ++i) {
            Ptr<TcpSocketBase> socket = DynamicCast<TcpSocketBase>(sockets.Get(i));
            Address peer;
            if (socket && socket->GetPeerName(peer) == 0 && InetSocketAddress::IsMatchingType(peer) &&
                InetSocketAddress::ConvertFrom(peer).GetIpv4() == target &&
                InetSocketAddress::ConvertFrom(peer).GetPort() == 1024) {
                if (!socket->TraceConnectWithoutContext("Tx", MakeCallback(&IslInterruptionExperiment::Transmitted, this))) {
                    throw std::runtime_error("TCP Tx trace unavailable.");
                }
                m_sender = socket;
                ++connected;
            }
        }
        if (connected != 1) { throw std::runtime_error("Expected exactly one TCP sender socket for the measured flow immediately after simulation start."); }
    }
    void Received(Ptr<const Packet> packet, const Address& from) {
        Ipv4Address source = m_topology->GetNodes().Get(m_source)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
        if (!InetSocketAddress::IsMatchingType(from) || InetSocketAddress::ConvertFrom(from).GetIpv4() != source) {
            throw std::runtime_error("Received data from an unexpected source at the TCP measurement sink.");
        }
        m_receivedBytes += packet->GetSize();
        m_received << "0," << Simulator::Now().GetNanoSeconds() << "," << m_receivedBytes << "\n";
    }
    void Transmitted(Ptr<const Packet> packet, const TcpHeader& header, Ptr<const TcpSocketBase>) {
        uint32_t bytes = packet->GetSize();
        if (bytes == 0) { return; } // Exclude control-only packets.
        uint32_t sequence = header.GetSequenceNumber().GetValue();
        if (m_transmittedPackets == 0) { m_highEnd = sequence; }
        // Unwrap around the current high-water mark. TCP's outstanding sequence
        // space is < 2^31; newly transmitted bytes advance monotonically. Count
        // overlap, including partially repeated segments and repeated retries.
        int64_t begin = m_highEnd + (header.GetSequenceNumber() - SequenceNumber32(static_cast<uint32_t>(m_highEnd)));
        uint32_t repeated = static_cast<uint32_t>(std::max<int64_t>(0, std::min<int64_t>(bytes, m_highEnd - begin)));
        m_highEnd = std::max(m_highEnd, begin + bytes);
        ++m_transmittedPackets;
        int64_t now = Simulator::Now().GetNanoSeconds();
        m_tx << "0," << now << "," << sequence << "," << bytes << "," << repeated << "\n";
        if (repeated != 0) {
            m_retransmissions << "0," << now << "," << sequence << "," << bytes << "," << repeated << "\n";
        }
    }
    Ptr<PointToPointLaserNetDevice> FindIsl(uint32_t from, uint32_t to) {
        Ptr<Node> node = m_topology->GetNodes().Get(from);
        for (uint32_t i = 0; i < node->GetNDevices(); ++i) {
            Ptr<PointToPointLaserNetDevice> device = DynamicCast<PointToPointLaserNetDevice>(node->GetDevice(i));
            if (!device || !device->GetChannel()) { continue; }
            Ptr<Channel> channel = device->GetChannel();
            for (uint32_t j = 0; j < channel->GetNDevices(); ++j) {
                if (channel->GetDevice(j)->GetNode()->GetId() == to) { return device; }
            }
        }
        throw std::invalid_argument("Configured ISL does not exist.");
    }
    Ptr<IslInterruptionErrorModel> InstallLossModel(Ptr<PointToPointLaserNetDevice> device) {
        PointerValue previous;
        device->GetAttribute("ReceiveErrorModel", previous);
        if (previous.GetObject()) { throw std::runtime_error("Refusing to replace an existing ISL error model."); }
        Ptr<IslInterruptionErrorModel> model = CreateObject<IslInterruptionErrorModel>();
        model->Disable();
        device->SetReceiveErrorModel(model);
        return model;
    }
    void SetInterrupted(bool interrupted) {
        if (interrupted) { m_errorA->Enable(); m_errorB->Enable(); }
        else { m_errorA->Disable(); m_errorB->Disable(); }
        m_active = interrupted;
        ++m_eventCount;
        m_events << Simulator::Now().GetNanoSeconds() << "," << (interrupted ? "down" : "up")
                 << "," << m_a << "," << m_b << "\n";
    }
    void DropAtA(Ptr<const Packet> packet) { RecordDrop(packet, m_b, m_a); }
    void DropAtB(Ptr<const Packet> packet) { RecordDrop(packet, m_a, m_b); }
    void RecordDrop(Ptr<const Packet> packet, uint32_t from, uint32_t to) {
        if (m_active) {
            m_drops << Simulator::Now().GetNanoSeconds() << "," << from << "," << to << "," << packet->GetSize() << "\n";
        }
    }

    Ptr<BasicSimulation> m_simulation;
    Ptr<TopologySatelliteNetwork> m_topology;
    Ptr<TcpSocketBase> m_sender;
    Ptr<IslInterruptionErrorModel> m_errorA, m_errorB;
    bool m_measure = false, m_outage = false, m_active = false;
    uint32_t m_source = 0, m_target = 0, m_a = 0, m_b = 0, m_eventCount = 0;
    uint64_t m_receivedBytes = 0, m_transmittedPackets = 0;
    int64_t m_highEnd = 0;
    std::ofstream m_received, m_tx, m_retransmissions, m_events, m_drops;
};

} // namespace ns3
#endif
